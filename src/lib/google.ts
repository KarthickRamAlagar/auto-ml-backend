import type { Config, Env } from "../env";
import { fromB64Url } from "./crypto";
import { HttpError } from "./http";

const JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const KV_KEY = "google:jwks";
const dec = new TextDecoder();

interface Jwk extends JsonWebKey {
  kid?: string;
}

let memo: { at: number; keys: Jwk[] } | null = null;

async function loadKeys(env: Env, force: boolean): Promise<Jwk[]> {
  if (!force && memo && Date.now() - memo.at < 3_600_000) return memo.keys;
  if (!force) {
    const cached = await env.CACHE.get(KV_KEY, "json");
    if (cached && Array.isArray((cached as { keys?: Jwk[] }).keys)) {
      memo = { at: Date.now(), keys: (cached as { keys: Jwk[] }).keys };
      return memo.keys;
    }
  }
  const res = await fetch(JWKS_URL, { cf: { cacheTtl: 3600 } } as RequestInit);
  if (!res.ok) throw new HttpError(503, "Google sign-in is temporarily unavailable. Try again shortly.");
  const body = (await res.json()) as { keys?: Jwk[] };
  const keys = body.keys ?? [];
  memo = { at: Date.now(), keys };
  await env.CACHE.put(KV_KEY, JSON.stringify({ keys }), { expirationTtl: 21_600 });
  return keys;
}

export interface GoogleIdentity {
  sub: string;
  email: string;
  emailVerified: boolean;
  name: string | null;
}

/** Verify a Google Identity Services ID token (RS256) completely: signature, issuer, audience, expiry, verified e-mail. */
export async function verifyGoogleIdToken(env: Env, cfg: Config, token: string, nowSec: number): Promise<GoogleIdentity> {
  const invalid = () => new HttpError(401, "Google sign-in failed. Please try again.");
  if (!cfg.googleClientId) throw new HttpError(503, "Google sign-in is not configured on this server.");
  const parts = token.split(".");
  if (parts.length !== 3) throw invalid();
  const [h, p, s] = parts as [string, string, string];
  let header: { alg?: string; kid?: string };
  let payload: { iss?: string; aud?: string; exp?: number; sub?: string; email?: string; email_verified?: boolean | string; name?: string };
  try {
    header = JSON.parse(dec.decode(fromB64Url(h)));
    payload = JSON.parse(dec.decode(fromB64Url(p)));
  } catch {
    throw invalid();
  }
  if (header.alg !== "RS256" || !header.kid) throw invalid();

  let keys = await loadKeys(env, false);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    keys = await loadKeys(env, true); // Google rotated its keys
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw invalid();
  const key = await crypto.subtle.importKey("jwk", { ...jwk, alg: "RS256", ext: true } as JsonWebKey, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, fromB64Url(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) throw invalid();

  if (payload.iss !== "accounts.google.com" && payload.iss !== "https://accounts.google.com") throw invalid();
  if (payload.aud !== cfg.googleClientId) throw invalid();
  if (typeof payload.exp !== "number" || payload.exp <= nowSec) throw invalid();
  if (!payload.sub || !payload.email) throw invalid();
  const verified = payload.email_verified === true || payload.email_verified === "true";
  if (!verified) throw new HttpError(403, "Your Google email address is not verified.");
  return { sub: payload.sub, email: payload.email.toLowerCase(), emailVerified: true, name: payload.name ?? null };
}
