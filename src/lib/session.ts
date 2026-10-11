import type { Context } from "hono";
import type { AppEnv, AuthUser, Config, Env } from "../env";
import { config } from "../env";
import { randomId, randomToken, sha256Hex, signJwt } from "./crypto";
import { cookie, now, readCookie } from "./http";

export const ACCESS_TTL = 10 * 60; // seconds; the short-lived signed cookie
export const REFRESH_TTL = 30 * 24 * 3600; // a refresh session lasts 30 days (sliding on use)
const GRACE_SECONDS = 15; // two tabs refreshing together may present the previous secret once

export interface UserRow {
  id: string;
  username: string;
  email: string;
  email_verified: number;
  status: string;
}

export const cookieOpts = (cfg: Config) => ({ secure: cfg.isProd });

async function mintAccess(env: Env, u: UserRow, sid: string): Promise<string> {
  const iat = Math.floor(now());
  return signJwt(env.JWT_SECRET, { sub: u.id, em: u.email, un: u.username, ev: u.email_verified === 1, sid, iat, exp: iat + ACCESS_TTL });
}

function setCookies(headers: Headers, cfg: Config, access: string, refresh: string): void {
  const o = cookieOpts(cfg);
  headers.append("Set-Cookie", cookie("at", access, { ...o, maxAge: ACCESS_TTL, path: "/", sameSite: "Lax" }));
  headers.append("Set-Cookie", cookie("rt", refresh, { ...o, maxAge: REFRESH_TTL, path: "/api/auth", sameSite: "Strict" }));
}

export function clearCookies(headers: Headers, cfg: Config): void {
  const o = cookieOpts(cfg);
  headers.append("Set-Cookie", cookie("at", "", { ...o, maxAge: 0, path: "/", sameSite: "Lax" }));
  headers.append("Set-Cookie", cookie("rt", "", { ...o, maxAge: 0, path: "/api/auth", sameSite: "Strict" }));
}

/** Start a refresh session and attach both cookies to `headers`. */
export async function startSession(c: Context<AppEnv>, u: UserRow, headers: Headers): Promise<void> {
  const cfg = config(c.env);
  const sid = randomId();
  const secret = randomToken(32);
  const t = now();
  await c.env.DB.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, created_at, last_used_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(sid, u.id, await sha256Hex(secret), t, t, t + REFRESH_TTL, c.get("ip"), (c.req.header("user-agent") ?? "").slice(0, 200))
    .run();
  setCookies(headers, cfg, await mintAccess(c.env, u, sid), `${sid}.${secret}`);
}

export type RefreshResult = { ok: true; user: UserRow } | { ok: false; reason: string };

/** Rotate the refresh secret and issue a fresh access cookie. Replaying an old secret revokes the session. */
export async function refreshSession(c: Context<AppEnv>, headers: Headers): Promise<RefreshResult> {
  const cfg = config(c.env);
  const raw = readCookie(c.req.header("cookie") ?? null, "rt");
  if (!raw || !raw.includes(".")) return { ok: false, reason: "no_session" };
  const [sid, secret] = [raw.slice(0, raw.indexOf(".")), raw.slice(raw.indexOf(".") + 1)];
  if (!/^[a-f0-9]{20}$/.test(sid) || secret.length < 20 || secret.length > 100) return { ok: false, reason: "bad_session" };

  const s = await c.env.DB.prepare("SELECT * FROM sessions WHERE id = ?").bind(sid).first<{ user_id: string; token_hash: string; prev_hash: string | null; rotated_at: number | null; expires_at: number; revoked_at: number | null }>();
  const t = now();
  if (!s || s.revoked_at !== null || s.expires_at <= t) return { ok: false, reason: "expired" };

  const hash = await sha256Hex(secret);
  const isCurrent = hash === s.token_hash;
  const isPrevInGrace = !isCurrent && s.prev_hash !== null && hash === s.prev_hash && s.rotated_at !== null && t - s.rotated_at <= GRACE_SECONDS;
  if (!isCurrent && !isPrevInGrace) {
    // A secret that was already rotated away is being replayed: assume theft and end the session.
    await c.env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ?").bind(t, sid).run();
    return { ok: false, reason: "reuse" };
  }
  const u = await c.env.DB.prepare("SELECT id, username, email, email_verified, status FROM users WHERE id = ?").bind(s.user_id).first<UserRow>();
  if (!u || u.status !== "active") return { ok: false, reason: "suspended" };

  const next = randomToken(32);
  await c.env.DB.prepare("UPDATE sessions SET token_hash = ?, prev_hash = ?, rotated_at = ?, last_used_at = ?, expires_at = ? WHERE id = ?")
    .bind(await sha256Hex(next), s.token_hash, t, t, t + REFRESH_TTL, sid)
    .run();
  setCookies(headers, cfg, await mintAccess(c.env, u, sid), `${sid}.${next}`);
  return { ok: true, user: u };
}

export async function revokeSession(env: Env, sid: string): Promise<void> {
  await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(now(), sid).run();
}

export async function revokeAllSessions(env: Env, userId: string): Promise<void> {
  await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now(), userId).run();
}

export const toAuthUser = (claims: { sub: string; em: string; un: string; ev: boolean; sid: string }, cfg: Config): AuthUser => ({
  id: claims.sub,
  email: claims.em,
  username: claims.un,
  verified: claims.ev,
  isAdmin: claims.ev && cfg.adminEmails.has(claims.em.toLowerCase()),
  sessionId: claims.sid,
});

export async function audit(env: Env, actor: string | null, action: string, target: string | null, ip: string | null, detail?: unknown): Promise<void> {
  try {
    await env.DB.prepare("INSERT INTO audit_log (ts, actor, action, target, ip, detail) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(now(), actor, action, target, ip, detail === undefined ? null : JSON.stringify(detail).slice(0, 1000))
      .run();
  } catch (e) {
    console.error("audit failed", String(e));
  }
}
