import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../env";
import { config } from "../env";
import { HttpError } from "../lib/http";

const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

/** Headers for every API response: no caching of private data, no sniffing, no framing. */
export const apiHeaders: MiddlewareHandler<AppEnv> = async (c, next) => {
  await next();
  const h = c.res.headers;
  h.set("Cache-Control", "no-store");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "strict-origin-when-cross-origin");
  h.set("Cross-Origin-Resource-Policy", "same-origin");
  h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  h.set("X-Request-Id", c.get("reqId"));
};

/**
 * CSRF defence for cookie auth: a state-changing request must come from this site. Browsers always send Origin (or
 * Sec-Fetch-Site) on cross-site posts, so a forged request from another website is rejected. SameSite cookies add a second layer.
 */
export const sameSiteOnly: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (SAFE.has(c.req.method)) return next();
  const cfg = config(c.env);
  const origin = c.req.header("origin");
  const fetchSite = c.req.header("sec-fetch-site");
  const self = new URL(c.req.url).origin;
  const allowed = new Set([self, cfg.appUrl]);
  if (!cfg.isProd) allowed.add("http://localhost:5173").add("http://127.0.0.1:5173");
  if (origin) {
    if (!allowed.has(origin)) throw new HttpError(403, "Cross-site request blocked.");
  } else if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw new HttpError(403, "Cross-site request blocked.");
  } else if (!origin && !fetchSite && cfg.isProd) {
    throw new HttpError(403, "Missing Origin header.");
  }
  return next();
};
