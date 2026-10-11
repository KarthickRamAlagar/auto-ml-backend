import type { Config, Env } from "../env";

const enc = new TextEncoder();
const dec = new TextDecoder();

export const toB64 = (buf: ArrayBuffer | Uint8Array): string => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};
export const fromB64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const toB64Url = (buf: ArrayBuffer | Uint8Array): string => toB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromB64Url = (s: string): Uint8Array => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
};
export const hex = (buf: ArrayBuffer | Uint8Array): string =>
  [...(buf instanceof Uint8Array ? buf : new Uint8Array(buf))].map((b) => b.toString(16).padStart(2, "0")).join("");

export const randomToken = (bytes = 32): string => toB64Url(crypto.getRandomValues(new Uint8Array(bytes)));
export const randomId = (): string => hex(crypto.getRandomValues(new Uint8Array(10))); // 20 hex chars

export async function sha256Hex(text: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

export async function hmacHex(secret: string, message: string): Promise<string> {
  return hex(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(message)));
}

/** Constant-time string comparison (hashes first so the length never leaks). */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

// --------------------------------------------------------------------------- passwords
// PBKDF2-SHA256 over HMAC(pepper, password): a database leak alone cannot be cracked offline without the pepper.
async function pbkdf2(env: Env, password: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const pre = await crypto.subtle.sign("HMAC", await hmacKey(env.PASSWORD_PEPPER), enc.encode(password.normalize("NFKC")));
  const key = await crypto.subtle.importKey("raw", pre, "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
}

export async function hashPassword(env: Env, cfg: Config, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2(env, password, salt, cfg.pbkdf2Iterations);
  return `pbkdf2$sha256$${cfg.pbkdf2Iterations}$${toB64(salt)}$${toB64(bits)}`;
}

export async function verifyPassword(env: Env, password: string, stored: string): Promise<{ ok: boolean; iterations: number }> {
  const [scheme, , iterStr, saltB64, hashB64] = stored.split("$");
  const iterations = Number(iterStr);
  if (scheme !== "pbkdf2" || !Number.isInteger(iterations) || iterations < 1 || iterations > 100_000 || !saltB64 || !hashB64) {
    return { ok: false, iterations: 0 };
  }
  const bits = await pbkdf2(env, password, fromB64(saltB64), iterations);
  return { ok: await safeEqual(toB64(bits), hashB64), iterations };
}

// A throw-away hash so a login for an unknown e-mail costs the same time as a real one.
export async function burnPasswordCheck(env: Env, cfg: Config, password: string): Promise<void> {
  await pbkdf2(env, password, new Uint8Array(16), cfg.pbkdf2Iterations);
}

// --------------------------------------------------------------------------- JWT (HS256, access cookie)
export interface AccessClaims {
  sub: string;
  em: string;
  un: string;
  ev: boolean;
  sid: string;
  iat: number;
  exp: number;
}

export async function signJwt(secret: string, claims: AccessClaims): Promise<string> {
  const head = toB64Url(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = toB64Url(enc.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(`${head}.${body}`));
  return `${head}.${body}.${toB64Url(sig)}`;
}

export async function verifyJwt(secret: string, token: string, nowSec: number): Promise<AccessClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [head, body, sig] = parts as [string, string, string];
  try {
    const h = JSON.parse(dec.decode(fromB64Url(head))) as { alg?: string };
    if (h.alg !== "HS256") return null; // never accept "none" or any other algorithm
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), fromB64Url(sig), enc.encode(`${head}.${body}`));
    if (!ok) return null;
    const claims = JSON.parse(dec.decode(fromB64Url(body))) as AccessClaims;
    if (typeof claims.exp !== "number" || claims.exp <= nowSec || typeof claims.sub !== "string") return null;
    return claims;
  } catch {
    return null;
  }
}
