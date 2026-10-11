import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import type { ZodType } from "zod";
import type { AppEnv, Env } from "../env";
import { config } from "../env";
import { burnPasswordCheck, hashPassword, randomId, randomToken, sha256Hex, verifyPassword } from "../lib/crypto";
import { verifyGoogleIdToken } from "../lib/google";
import { HttpError, bad, now, readCookie } from "../lib/http";
import { enqueueMail, resetMail, verifyMail } from "../lib/mail";
import { assertNotLocked, clearKey, limit, recordFailure } from "../lib/ratelimit";
import { forgotBody, googleBody, loginBody, resetBody, signupBody, verifyBody } from "../lib/schemas";
import { audit, clearCookies, refreshSession, revokeAllSessions, revokeSession, startSession, type UserRow } from "../lib/session";
import { requireUser } from "../middleware/auth";

export const auth = new Hono<AppEnv>();

// Zod failures become { detail: { message, fields } } so the form can show the first problem and mark each field.
const validate = <T extends ZodType>(schema: T) =>
  zValidator("json", schema, (result) => {
    if (!result.success) {
      const fields: Record<string, string> = {};
      for (const i of result.error.issues) {
        const k = String(i.path[0] ?? "form");
        fields[k] ??= i.message;
      }
      throw new HttpError(422, { message: Object.values(fields)[0] ?? "Check the form.", fields });
    }
  });

type DbUser = UserRow & { password_hash: string | null; google_sub: string | null; contact: string | null; created_at: number };

const publicUser = (u: UserRow, cfgAdmins: Set<string>) => ({
  id: u.id,
  username: u.username,
  email: u.email,
  email_verified: u.email_verified === 1,
  is_admin: u.email_verified === 1 && cfgAdmins.has(u.email.toLowerCase()),
});

async function newAuthToken(env: Env, userId: string, kind: "verify" | "reset", ttlSec: number): Promise<string> {
  const raw = randomToken(32);
  const t = now();
  // one live token per kind: a fresh request replaces any earlier link
  await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_tokens WHERE user_id = ? AND kind = ?").bind(userId, kind),
    env.DB.prepare("INSERT INTO auth_tokens (id, user_id, kind, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)").bind(randomId(), userId, kind, await sha256Hex(raw), t, t + ttlSec),
  ]);
  return raw;
}

const devLink = (env: Env, path: string, token: string) => (!config(env).isProd && !env.RESEND_API_KEY ? `${config(env).appUrl}${path}?token=${encodeURIComponent(token)}` : undefined);

// --------------------------------------------------------------------------- sign up
auth.post("/signup", validate(signupBody), async (c) => {
  const cfg = config(c.env);
  const ip = c.get("ip");
  await limit(c.env, `signup:ip:${ip}`, 20, 3600, true, "sign-up attempts");
  const b = c.req.valid("json");

  const taken = await c.env.DB.prepare("SELECT email, username FROM users WHERE email = ? OR username = ?").bind(b.email, b.username).all<{ email: string; username: string }>();
  for (const r of taken.results) {
    if (r.email.toLowerCase() === b.email) throw new HttpError(409, { message: "An account with this email already exists. Try signing in.", fields: { email: "Already registered." } });
    if (r.username.toLowerCase() === b.username.toLowerCase()) throw new HttpError(409, { message: "That username is taken. Choose another.", fields: { username: "Already taken." } });
  }

  const id = randomId();
  const t = now();
  const hash = await hashPassword(c.env, cfg, b.password);
  try {
    await c.env.DB.prepare("INSERT INTO users (id, username, email, contact, password_hash, email_verified, created_at, updated_at, last_login_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)")
      .bind(id, b.username, b.email, b.contact, hash, t, t, t)
      .run();
  } catch (e) {
    if (/UNIQUE constraint failed/i.test(String((e as Error).message))) throw new HttpError(409, "That email or username is already registered.");
    throw e;
  }
  const user: UserRow = { id, username: b.username, email: b.email, email_verified: 0, status: "active" };

  const token = await newAuthToken(c.env, id, "verify", 24 * 3600);
  enqueueMail(c, cfg, verifyMail(cfg, b.email, b.username, token));
  await audit(c.env, id, "signup", b.email, ip);

  const headers = new Headers({ "Content-Type": "application/json" });
  await startSession(c, user, headers);
  return new Response(JSON.stringify({ user: publicUser(user, cfg.adminEmails), dev_verify_url: devLink(c.env, "/verify-email", token) }), { status: 201, headers });
});

// --------------------------------------------------------------------------- sign in
auth.post("/login", validate(loginBody), async (c) => {
  const cfg = config(c.env);
  const ip = c.get("ip");
  const { identifier, password } = c.req.valid("json");
  const ident = identifier.toLowerCase();
  const idKey = `login:id:${ident}`;
  const ipKey = `login:ip:${ip}`;
  await assertNotLocked(c.env, idKey, 8, "failed sign-in attempts");
  await assertNotLocked(c.env, ipKey, 80, "failed sign-in attempts from your network");

  const u = await c.env.DB.prepare("SELECT * FROM users WHERE " + (ident.includes("@") ? "email" : "username") + " = ?").bind(ident).first<DbUser>();
  let ok = false;
  let iterations = 0;
  if (u?.password_hash) {
    const r = await verifyPassword(c.env, password, u.password_hash);
    ok = r.ok;
    iterations = r.iterations;
  } else {
    await burnPasswordCheck(c.env, cfg, password); // same cost whether or not the account exists
  }
  if (!u || !ok) {
    await recordFailure(c.env, idKey, 8, 900);
    await recordFailure(c.env, ipKey, 80, 900);
    await audit(c.env, u?.id ?? null, "login_failed", ident, ip);
    throw new HttpError(401, "Incorrect email, username or password.");
  }
  if (u.status !== "active") throw new HttpError(403, "This account is suspended. Contact support.");

  await clearKey(c.env, idKey);
  const t = now();
  const rehash = iterations !== cfg.pbkdf2Iterations ? await hashPassword(c.env, cfg, password) : null;
  await c.env.DB.prepare("UPDATE users SET last_login_at = ?, updated_at = ?" + (rehash ? ", password_hash = ?" : "") + " WHERE id = ?")
    .bind(...(rehash ? [t, t, rehash, u.id] : [t, t, u.id]))
    .run();
  await audit(c.env, u.id, "login", u.email, ip);

  const headers = new Headers({ "Content-Type": "application/json" });
  await startSession(c, u, headers);
  return new Response(JSON.stringify({ user: publicUser(u, cfg.adminEmails) }), { headers });
});

// --------------------------------------------------------------------------- Google
auth.post("/google", validate(googleBody), async (c) => {
  const cfg = config(c.env);
  const ip = c.get("ip");
  await limit(c.env, `google:ip:${ip}`, 30, 60, false, "sign-in attempts");
  const { credential } = c.req.valid("json");
  const g = await verifyGoogleIdToken(c.env, cfg, credential, now());

  let u = await c.env.DB.prepare("SELECT * FROM users WHERE google_sub = ?").bind(g.sub).first<DbUser>();
  if (!u) {
    const byEmail = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(g.email).first<DbUser>();
    const t = now();
    if (byEmail) {
      // Google vouches for this address, so it also counts as verified. Link the identity to the existing account.
      // If that account was never verified, whoever created it may not own the address (a "pre-hijack"), so its
      // password is wiped and its sessions ended; the real owner now signs in with Google.
      const unverified = byEmail.email_verified !== 1;
      await c.env.DB.prepare("UPDATE users SET google_sub = ?, email_verified = 1, password_hash = " + (unverified ? "NULL" : "password_hash") + ", updated_at = ? WHERE id = ?").bind(g.sub, t, byEmail.id).run();
      if (unverified) await revokeAllSessions(c.env, byEmail.id);
      u = { ...byEmail, google_sub: g.sub, email_verified: 1, password_hash: unverified ? null : byEmail.password_hash };
    } else {
      const id = randomId();
      const base = (g.email.split("@")[0] ?? "user").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 22).padEnd(3, "0");
      let name = base;
      for (let i = 0; i < 6; i++) {
        const exists = await c.env.DB.prepare("SELECT 1 FROM users WHERE username = ?").bind(name).first();
        if (!exists) break;
        name = `${base}${Math.floor(1000 + Math.random() * 9000)}`;
      }
      try {
        await c.env.DB.prepare("INSERT INTO users (id, username, email, google_sub, email_verified, created_at, updated_at, last_login_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)")
          .bind(id, name, g.email, g.sub, t, t, t)
          .run();
      } catch (e) {
        if (/UNIQUE constraint failed/i.test(String((e as Error).message))) throw new HttpError(409, "Please try signing in again.");
        throw e;
      }
      u = (await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<DbUser>())!;
      await audit(c.env, id, "signup_google", g.email, ip);
    }
  }
  if (u.status !== "active") throw new HttpError(403, "This account is suspended. Contact support.");
  await c.env.DB.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now(), u.id).run();
  await audit(c.env, u.id, "login_google", u.email, ip);

  const headers = new Headers({ "Content-Type": "application/json" });
  await startSession(c, u, headers);
  return new Response(JSON.stringify({ user: publicUser(u, cfg.adminEmails) }), { headers });
});

// --------------------------------------------------------------------------- session refresh / sign out
auth.post("/refresh", async (c) => {
  await limit(c.env, `refresh:ip:${c.get("ip")}`, 60, 60, false, "refresh attempts");
  const headers = new Headers({ "Content-Type": "application/json" });
  const r = await refreshSession(c, headers);
  if (!r.ok) {
    clearCookies(headers, config(c.env));
    return new Response(JSON.stringify({ detail: { message: "Your session has ended. Please sign in again.", code: "session_ended" } }), { status: 401, headers });
  }
  return new Response(JSON.stringify({ user: publicUser(r.user, config(c.env).adminEmails) }), { headers });
});

auth.post("/logout", async (c) => {
  const headers = new Headers({ "Content-Type": "application/json" });
  const raw = readCookie(c.req.header("cookie") ?? null, "rt");
  const sid = raw?.split(".")[0];
  if (sid && /^[a-f0-9]{20}$/.test(sid)) await revokeSession(c.env, sid);
  clearCookies(headers, config(c.env));
  return new Response(JSON.stringify({ ok: true }), { headers });
});

auth.post("/logout-all", requireUser, async (c) => {
  const u = c.get("user")!;
  await revokeAllSessions(c.env, u.id);
  await audit(c.env, u.id, "logout_all", u.email, c.get("ip"));
  const headers = new Headers({ "Content-Type": "application/json" });
  clearCookies(headers, config(c.env));
  return new Response(JSON.stringify({ ok: true }), { headers });
});

// --------------------------------------------------------------------------- e-mail verification
auth.post("/verify-email", validate(verifyBody), async (c) => {
  await limit(c.env, `verify:ip:${c.get("ip")}`, 30, 3600, false, "verification attempts");
  const { token } = c.req.valid("json");
  const row = await c.env.DB.prepare("SELECT id, user_id, expires_at, used_at FROM auth_tokens WHERE token_hash = ? AND kind = 'verify'").bind(await sha256Hex(token)).first<{ id: string; user_id: string; expires_at: number; used_at: number | null }>();
  if (!row || row.used_at !== null || row.expires_at <= now()) throw bad("This verification link is invalid or has expired. Request a new one.", 400);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?").bind(now(), row.user_id),
    c.env.DB.prepare("UPDATE auth_tokens SET used_at = ? WHERE id = ?").bind(now(), row.id),
  ]);
  await audit(c.env, row.user_id, "email_verified", null, c.get("ip"));
  return c.json({ ok: true });
});

auth.post("/resend-verification", requireUser, async (c) => {
  const cfg = config(c.env);
  const u = c.get("user")!;
  await limit(c.env, `resend:${u.id}`, 3, 3600, true, "verification emails");
  const row = await c.env.DB.prepare("SELECT username, email, email_verified FROM users WHERE id = ?").bind(u.id).first<{ username: string; email: string; email_verified: number }>();
  if (!row) throw new HttpError(404, "Account not found.");
  if (row.email_verified === 1) return c.json({ ok: true, already_verified: true });
  const token = await newAuthToken(c.env, u.id, "verify", 24 * 3600);
  enqueueMail(c, cfg, verifyMail(cfg, row.email, row.username, token));
  return c.json({ ok: true, dev_verify_url: devLink(c.env, "/verify-email", token) });
});

// --------------------------------------------------------------------------- password reset
auth.post("/forgot", validate(forgotBody), async (c) => {
  const cfg = config(c.env);
  const ip = c.get("ip");
  await limit(c.env, `forgot:ip:${ip}`, 8, 3600, true, "reset requests");
  const { email } = c.req.valid("json");
  await limit(c.env, `forgot:email:${email}`, 3, 3600, true, "reset requests for this email");
  const u = await c.env.DB.prepare("SELECT id, username, email, password_hash FROM users WHERE email = ? AND status = 'active'").bind(email).first<{ id: string; username: string; email: string }>();
  let dev: string | undefined;
  if (u) {
    const token = await newAuthToken(c.env, u.id, "reset", 3600);
    enqueueMail(c, cfg, resetMail(cfg, u.email, u.username, token));
    await audit(c.env, u.id, "reset_requested", u.email, ip);
    dev = devLink(c.env, "/reset-password", token);
  }
  // The same answer whether or not the address exists, so this cannot be used to find registered emails.
  return c.json({ ok: true, message: "If that email has an account, a reset link is on its way.", dev_reset_url: dev });
});

auth.post("/reset", validate(resetBody), async (c) => {
  const cfg = config(c.env);
  await limit(c.env, `reset:ip:${c.get("ip")}`, 20, 3600, false, "reset attempts");
  const { token, password } = c.req.valid("json");
  const row = await c.env.DB.prepare("SELECT id, user_id, expires_at, used_at FROM auth_tokens WHERE token_hash = ? AND kind = 'reset'").bind(await sha256Hex(token)).first<{ id: string; user_id: string; expires_at: number; used_at: number | null }>();
  if (!row || row.used_at !== null || row.expires_at <= now()) throw bad("This reset link is invalid or has expired. Request a new one.", 400);
  const hash = await hashPassword(c.env, cfg, password);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE users SET password_hash = ?, email_verified = 1, updated_at = ? WHERE id = ?").bind(hash, now(), row.user_id), // the link proves the inbox is theirs
    c.env.DB.prepare("UPDATE auth_tokens SET used_at = ? WHERE id = ?").bind(now(), row.id),
  ]);
  await revokeAllSessions(c.env, row.user_id); // everyone signed in with the old password is signed out
  await audit(c.env, row.user_id, "password_reset", null, c.get("ip"));
  return c.json({ ok: true });
});
