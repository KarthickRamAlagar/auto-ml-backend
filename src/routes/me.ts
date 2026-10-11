import { Hono } from "hono";
import type { AppEnv } from "../env";
import { HttpError, now } from "../lib/http";
import { FREE_REPORTS, FREE_MODELS, PAID_MODELS, QUIZ_SECONDS, REPORT_PRICE, snapshot, normalize, type UsageDoc } from "../lib/limits";

export const me = new Hono<AppEnv>();

interface UserUsage extends Record<string, unknown> {
  username: string;
  email_verified: number;
  contact: string | null;
  window_start: number | null;
  free_used: number;
  paid_used: number;
  verified_spend: number;
  reports_used: number;
  paid_blocked: number;
}

async function load(c: { env: AppEnv["Bindings"]; get: (k: "user") => AppEnv["Variables"]["user"] }) {
  const u = c.get("user")!;
  const [row, vip] = await c.env.DB.batch<Record<string, unknown>>([
    c.env.DB.prepare("SELECT username, contact, email_verified, window_start, free_used, paid_used, verified_spend, reports_used, paid_blocked FROM users WHERE id = ?").bind(u.id),
    c.env.DB.prepare("SELECT 1 AS v FROM vip WHERE email = ?").bind(u.email),
  ]);
  const r = row!.results[0] as UserUsage | undefined;
  if (!r) throw new HttpError(401, { message: "Account not found. Please sign in again.", code: "session_ended" });
  const usage: UsageDoc = {
    window_start: r.window_start,
    free_used: r.free_used,
    paid_used: r.paid_used,
    verified_spend: r.verified_spend,
    reports_used: r.reports_used,
    paid_blocked: r.paid_blocked === 1,
  };
  const isVip = u.isAdmin || (vip!.results.length > 0);
  // an expired window resets the counters; save that so the engine sees the same numbers
  if (normalize(usage, now())) {
    await c.env.DB.prepare("UPDATE users SET window_start = NULL, free_used = 0, paid_used = 0, updated_at = ? WHERE id = ?").bind(now(), u.id).run();
  }
  return { u, r, usage, isVip };
}

me.get("/me", async (c) => {
  const { u, r, usage, isVip } = await load(c);
  return c.json({
    uid: u.id,
    email: u.email,
    username: r.username,
    contact: r.contact,
    email_verified: r.email_verified === 1,
    is_admin: u.isAdmin,
    is_vip: isVip,
    usage: snapshot(usage, now(), isVip),
    limits: { free: FREE_MODELS, paid: PAID_MODELS, quiz_seconds: QUIZ_SECONDS, report_price: REPORT_PRICE, free_reports: FREE_REPORTS },
  });
});

me.get("/usage", async (c) => {
  const { usage, isVip } = await load(c);
  return c.json(snapshot(usage, now(), isVip));
});
