import { beforeAll, describe, expect, it, vi } from "vitest";
import { Client, E, j, signedUp, uniq } from "./helpers";

const enc = new TextEncoder();
const b64u = (b: ArrayBuffer | Uint8Array | string) => {
  const bytes = typeof b === "string" ? enc.encode(b) : b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

let priv: CryptoKey;
const AUD = "test-client-id.apps.googleusercontent.com";

async function idToken(claims: Record<string, unknown>, kid = "k1", key = priv): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: "RS256", kid, typ: "JWT" }));
  const body = b64u(JSON.stringify({ iss: "https://accounts.google.com", aud: AUD, sub: uniq("sub"), email_verified: true, exp: now + 600, iat: now, ...claims }));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(`${head}.${body}`));
  return `${head}.${body}.${b64u(sig)}`;
}

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  priv = pair.privateKey;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  const jwks = JSON.stringify({ keys: [{ ...jwk, kid: "k1", use: "sig" }] });
  await E.CACHE.put("google:jwks", jwks);
  // Hermetic: when the Worker refetches Google's key list (unknown kid), answer with our test keys, never the network.
  const real = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    if (url.startsWith("https://www.googleapis.com/oauth2/v3/certs")) return Promise.resolve(new Response(jwks, { headers: { "Content-Type": "application/json" } }));
    return real(input as RequestInfo, init);
  });
});

describe("Google sign-in", () => {
  it("creates an account from a valid ID token and signs the user in", async () => {
    const email = `${uniq("g")}@gmail.com`;
    const c = new Client();
    const res = await c.post("/api/auth/google", { credential: await idToken({ email, name: "G User" }) });
    expect(res.status).toBe(200);
    const me = await j(await c.get("/api/me"));
    expect(me.email).toBe(email);
    expect(me.email_verified).toBe(true);
    expect(me.username.length).toBeGreaterThanOrEqual(3);
  });

  it("signs the same Google user into the same account next time", async () => {
    const sub = uniq("sub");
    const email = `${uniq("g")}@gmail.com`;
    const a = new Client();
    await a.post("/api/auth/google", { credential: await idToken({ email, sub }) });
    const b = new Client();
    await b.post("/api/auth/google", { credential: await idToken({ email, sub }) });
    expect((await j(await a.get("/api/me"))).uid).toBe((await j(await b.get("/api/me"))).uid);
  });

  it("rejects wrong audience, wrong issuer, expired, unverified e-mail and bad signatures", async () => {
    const email = `${uniq("g")}@gmail.com`;
    const bad = [
      await idToken({ email, aud: "someone-elses-client-id" }),
      await idToken({ email, iss: "https://evil.example" }),
      await idToken({ email, exp: Math.floor(Date.now() / 1000) - 10 }),
      await idToken({ email, email_verified: false }),
      await idToken({ email }, "unknown-kid"),
    ];
    const other = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    bad.push(await idToken({ email }, "k1", other.privateKey)); // signed with a key Google never published
    for (const t of bad) expect((await new Client().post("/api/auth/google", { credential: t })).status).toBeGreaterThanOrEqual(401);
    const none = `${b64u(JSON.stringify({ alg: "none", kid: "k1" }))}.${b64u(JSON.stringify({ iss: "https://accounts.google.com", aud: AUD, sub: "x", email, email_verified: true, exp: 9999999999 }))}.`;
    expect((await new Client().post("/api/auth/google", { credential: none.padEnd(30, "x") })).status).toBe(401);
  });

  it("wipes the password of an UNVERIFIED account when its address signs in with Google (pre-hijack)", async () => {
    const { c: attacker, body } = await signedUp(); // someone registered the victim's address with their own password
    const victim = new Client();
    expect((await victim.post("/api/auth/google", { credential: await idToken({ email: body.email }) })).status).toBe(200);
    expect((await new Client().post("/api/auth/login", { identifier: body.email, password: body.password })).status).toBe(401);
    expect((await attacker.post("/api/auth/refresh")).status).toBe(401); // attacker's session is gone
  });

  it("keeps the password of an already verified account when Google is linked", async () => {
    const { c, body, json } = await signedUp();
    await c.post("/api/auth/verify-email", { token: new URL(json.dev_verify_url!).searchParams.get("token") });
    expect((await new Client().post("/api/auth/google", { credential: await idToken({ email: body.email }) })).status).toBe(200);
    expect((await new Client().post("/api/auth/login", { identifier: body.email, password: body.password })).status).toBe(200);
  });
});
