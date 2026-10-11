// Port of backend/app/limits.py (usage windows). The Worker answers /api/me and /api/usage on its own so the busiest
// page-load calls never wait for the Python engine. test/limits.test.ts pins the numbers to the Python source.
export const FREE_MODELS = 10;
export const PAID_MODELS = 15;
export const BASE_WINDOW_SECONDS = 5 * 3600 + 40 * 60; // 20,400 s
export const REPORT_PRICE = 5;
export const FREE_REPORTS = 2;
export const QUIZ_SECONDS = 75;

export interface UsageDoc {
  window_start: number | null;
  free_used: number;
  paid_used: number;
  verified_spend: number;
  reports_used: number;
  paid_blocked: boolean;
}

export function windowSeconds(verifiedSpend: number): number {
  if (verifiedSpend > 100) return Math.trunc(BASE_WINDOW_SECONDS * 0.94);
  if (verifiedSpend > 50) return Math.trunc(BASE_WINDOW_SECONDS * 0.97);
  return BASE_WINDOW_SECONDS;
}

/** Reset the counters if the window has run out. Returns true when something changed (the caller saves it). */
export function normalize(u: UsageDoc, now: number): boolean {
  if (u.window_start !== null && now >= u.window_start + windowSeconds(u.verified_spend)) {
    u.window_start = null;
    u.free_used = 0;
    u.paid_used = 0;
    return true;
  }
  return false;
}

export function snapshot(u: UsageDoc, now: number, unlimited: boolean) {
  normalize(u, now);
  const win = windowSeconds(u.verified_spend);
  const start = u.window_start;
  const freeLeft = Math.max(0, FREE_MODELS - u.free_used);
  const paidLeft = Math.max(0, PAID_MODELS - u.paid_used);
  return {
    unlimited,
    free_limit: FREE_MODELS,
    paid_limit: PAID_MODELS,
    free_used: u.free_used,
    paid_used: u.paid_used,
    free_remaining: freeLeft,
    paid_remaining: paidLeft,
    total_remaining: freeLeft + paidLeft,
    window_seconds: win,
    window_start: start,
    resets_at: start !== null ? start + win : null,
    now,
    verified_spend: u.verified_spend,
    reports_used: u.reports_used,
    paid_blocked: u.paid_blocked,
  };
}
