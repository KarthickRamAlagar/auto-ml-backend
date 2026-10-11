import { describe, expect, it } from "vitest";
import { Client, E, j, signedUp, uniq, validSignup } from "./helpers";

describe("sign up", () => {
  it("creates the account, starts a session and returns the profile", async () => {
    const { c, body, json } = await signedUp();
    expect(json.user.email).toBe(body.email);
    expect(c.jar.has("at") && c.jar.has("rt")).toBe(true);
    const me = await j(await c.get("/api/me"));
    expect(me.email).toBe(body.email);
    expect(me.username).toBe(body.username);
    expect(me.is_admin).toBe(false);
    expect(me.usage.free_remaining).toBe(10);
    expect(me.limits.paid).toBe(15);
    const row = await E.DB.prepare("SELECT password_hash, contact FROM users WHERE id = ?").bind(json.user.id).first<{ password_hash: string; contact: string }>();
    expect(row!.password_hash.startsWith("pbkdf2$sha256$")).toBe(true);
    expect(row!.password_hash).not.toContain(String(body.password));
    expect(row!.contact).toBe("+919876543210"); // spaces stripped
  });

  it("rejects bad input with field messages", async () => {
    const c = new Client();
    const cases: [Record<string, unknown>, string][] = [
      [{ username: "a b" }, "username"],
      [{ username: "ab" }, "username"],
      [{ email: "not-an-email" }, "email"],
      [{ contact: "12" }, "contact"],
      [{ password: "short1" }, "password"],
      [{ password: "alllettersonly" }, "password"],
      [{ password: "Password123" }, "password"],
    ];
    for (const [over, field] of cases) {
      const res = await c.post("/api/auth/signup", validSignup(over));
      expect(res.status, JSON.stringify(over)).toBe(422);
      const d = (await j(res)).detail;
      expect(d.fields[field]).toBeTruthy();
      expect(typeof d.message).toBe("string");
    }
  });

  it("refuses a duplicate email or username", async () => {
    const { body } = await signedUp();
    const c = new Client();
    const dupEmail = await c.post("/api/auth/signup", validSignup({ email: String(body.email).toUpperCase() }));
    expect(dupEmail.status).toBe(409);
    const dupName = await c.post("/api/auth/signup", validSignup({ username: String(body.username).toUpperCase() }));
    expect(dupName.status).toBe(409);
  });

  it("does not let the admin e-mail act as admin until it is verified", async () => {
    const { c, json } = await signedUp({ email: "admin@example.com", username: uniq("adm") }).catch(async () => {
      // the admin address may already exist from an earlier run in this file
      throw new Error("admin address already registered");
    });
    expect((await j(await c.get("/api/me"))).is_admin).toBe(false);
    const url = new URL(json.dev_verify_url!);
    expect((await c.post("/api/auth/verify-email", { token: url.searchParams.get("token") })).status).toBe(200);
    await c.post("/api/auth/refresh"); // new access cookie carries the verified flag
    expect((await j(await c.get("/api/me"))).is_admin).toBe(true);
  });
});

describe("sign in", () => {
  it("accepts e-mail or username, rejects a wrong password with one generic message", async () => {
    const { body } = await signedUp();
    const byEmail = new Client();
    expect((await byEmail.post("/api/auth/login", { identifier: body.email, password: body.password })).status).toBe(200);
    const byName = new Client();
    expect((await byName.post("/api/auth/login", { identifier: String(body.username).toUpperCase(), password: body.password })).status).toBe(200);
    const wrong = await new Client().post("/api/auth/login", { identifier: body.email, password: "Wrong-password-1" });
    const ghost = await new Client().post("/api/auth/login", { identifier: `${uniq("ghost")}@example.com`, password: "Wrong-password-1" });
    expect(wrong.status).toBe(401);
    expect(ghost.status).toBe(401);
    expect((await j(wrong)).detail).toBe((await j(ghost)).detail);
  });

  it("locks an account after 8 failures, even for the right password", async () => {
    const { body } = await signedUp();
    const c = new Client();
    for (let i = 0; i < 8; i++) expect((await c.post("/api/auth/login", { identifier: body.email, password: "Nope-nope-123" })).status).toBe(401);
    const locked = await c.post("/api/auth/login", { identifier: body.email, password: body.password });
    expect(locked.status).toBe(429);
    expect(Number(locked.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("blocks suspended accounts", async () => {
    const { body, json } = await signedUp();
    await E.DB.prepare("UPDATE users SET status = 'suspended' WHERE id = ?").bind(json.user.id).run();
    expect((await new Client().post("/api/auth/login", { identifier: body.email, password: body.password })).status).toBe(403);
  });
});

describe("sessions", () => {
  it("answers 401 without a cookie, and with a tampered or foreign token", async () => {
    const c = new Client();
    const r = await c.get("/api/me");
    expect(r.status).toBe(401);
    expect((await j(r)).detail.code).toBe("unauthenticated");
    c.jar.set("at", "aaa.bbb.ccc");
    const r2 = await c.get("/api/me");
    expect(r2.status).toBe(401);
    expect((await j(r2)).detail.code).toBe("token_expired");
    // alg=none forgery
    const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    c.jar.set("at", `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "x", em: "a@b.c", un: "x", ev: true, sid: "s", iat: 1, exp: 9999999999 })}.`);
    expect((await c.get("/api/me")).status).toBe(401);
  });

  it("rotates the refresh secret and rejects a replayed one", async () => {
    const { c } = await signedUp();
    const first = c.jar.get("rt")!;
    await new Promise((r) => setTimeout(r, 20));
    expect((await c.post("/api/auth/refresh")).status).toBe(200);
    const second = c.jar.get("rt")!;
    expect(second).not.toBe(first);
    expect((await c.get("/api/me")).status).toBe(200);

    // Replay of the old secret after the grace window: force the window to have passed.
    const sid = first.split(".")[0]!;
    await E.DB.prepare("UPDATE sessions SET rotated_at = rotated_at - 120 WHERE id = ?").bind(sid).run();
    const thief = new Client();
    thief.jar.set("rt", first);
    expect((await thief.post("/api/auth/refresh")).status).toBe(401);
    // ...and the whole session is now revoked, so the victim's own refresh stops working too
    expect((await c.post("/api/auth/refresh")).status).toBe(401);
  });

  it("allows the previous secret once inside the grace window (two tabs)", async () => {
    const { c } = await signedUp();
    const old = c.jar.get("rt")!;
    expect((await c.post("/api/auth/refresh")).status).toBe(200);
    const tab2 = new Client();
    tab2.jar.set("rt", old);
    expect((await tab2.post("/api/auth/refresh")).status).toBe(200);
  });

  it("signs out: the refresh session is revoked", async () => {
    const { c } = await signedUp();
    const rt = c.jar.get("rt")!;
    expect((await c.post("/api/auth/logout")).status).toBe(200);
    expect(c.jar.has("rt")).toBe(false);
    const again = new Client();
    again.jar.set("rt", rt);
    expect((await again.post("/api/auth/refresh")).status).toBe(401);
  });

  it("rejects cross-site writes (CSRF)", async () => {
    const { c } = await signedUp();
    const evil = await c.req("POST", "/api/auth/logout-all", {}, { origin: "https://evil.example" });
    expect(evil.status).toBe(403);
    const noOrigin = await c.req("POST", "/api/feedback", { rating: 5 }, { origin: null, headers: { "Sec-Fetch-Site": "cross-site" } });
    expect(noOrigin.status).toBe(403);
  });

  it("sets HttpOnly, SameSite cookies", async () => {
    const res = await new Client().post("/api/auth/signup", validSignup());
    const cookies = res.headers.getSetCookie();
    expect(cookies.length).toBe(2);
    for (const c of cookies) expect(c).toMatch(/HttpOnly/);
    expect(cookies.find((c) => c.startsWith("rt="))).toMatch(/SameSite=Strict.*|.*SameSite=Strict/);
    expect(cookies.find((c) => c.startsWith("rt="))).toMatch(/Path=\/api\/auth/);
  });
});

describe("password reset and e-mail verification", () => {
  it("resets the password, ends old sessions and burns the link", async () => {
    const { c, body, json } = await signedUp();
    const rt = c.jar.get("rt")!;
    const f = await new Client().post("/api/auth/forgot", { email: body.email });
    expect(f.status).toBe(200);
    const token = new URL((await j(f)).dev_reset_url).searchParams.get("token")!;
    const weak = await new Client().post("/api/auth/reset", { token, password: "short" });
    expect(weak.status).toBe(422);
    const ok = await new Client().post("/api/auth/reset", { token, password: "Brand-new-pass-77" });
    expect(ok.status).toBe(200);
    expect((await new Client().post("/api/auth/reset", { token, password: "Another-pass-88" })).status).toBe(400); // single use
    const old = new Client();
    old.jar.set("rt", rt);
    expect((await old.post("/api/auth/refresh")).status).toBe(401); // old session revoked
    expect((await new Client().post("/api/auth/login", { identifier: body.email, password: body.password })).status).toBe(401);
    expect((await new Client().post("/api/auth/login", { identifier: body.email, password: "Brand-new-pass-77" })).status).toBe(200);
    expect(json.user.id).toBeTruthy();
  });

  it("answers the same for unknown addresses (no account enumeration)", async () => {
    const known = (await signedUp()).body.email;
    const a = await j(await new Client().post("/api/auth/forgot", { email: known }));
    const b = await j(await new Client().post("/api/auth/forgot", { email: `${uniq("nobody")}@example.com` }));
    expect(a.message).toBe(b.message);
    expect(b.dev_reset_url).toBeUndefined();
  });

  it("verifies an e-mail address once", async () => {
    const { c, json } = await signedUp();
    const token = new URL(json.dev_verify_url!).searchParams.get("token")!;
    expect((await c.post("/api/auth/verify-email", { token })).status).toBe(200);
    expect((await c.post("/api/auth/verify-email", { token })).status).toBe(400);
    const row = await E.DB.prepare("SELECT email_verified FROM users WHERE id = ?").bind(json.user.id).first<{ email_verified: number }>();
    expect(row!.email_verified).toBe(1);
  });
});
