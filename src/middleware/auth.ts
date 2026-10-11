import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../env";
import { config } from "../env";
import { verifyJwt } from "../lib/crypto";
import { HttpError, now, readCookie } from "../lib/http";
import { toAuthUser } from "../lib/session";

/** Read the signed access cookie. 401 with code "token_expired" tells the app to call /api/auth/refresh once. */
export const requireUser: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = readCookie(c.req.header("cookie") ?? null, "at");
  const claims = token ? await verifyJwt(c.env.JWT_SECRET, token, now()) : null;
  if (!claims) throw new HttpError(401, { message: "Please sign in.", code: token ? "token_expired" : "unauthenticated" });
  c.set("user", toAuthUser(claims, config(c.env)));
  await next();
};

export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (!c.get("user")?.isAdmin) throw new HttpError(403, "Admin only.");
  await next();
};

/** Broad per-user request cap using Cloudflare's built-in limiter (no extra network hop). */
export const apiRateLimit: MiddlewareHandler<AppEnv> = async (c, next) => {
  const u = c.get("user");
  const key = u ? `u:${u.id}` : `ip:${c.get("ip")}`;
  if (c.env.API_LIMITER) {
    const { success } = await c.env.API_LIMITER.limit({ key });
    if (!success) throw new HttpError(429, { message: "Too many requests. Please slow down for a moment.", code: "rate_limited" }, { "Retry-After": "30" });
  }
  await next();
};
