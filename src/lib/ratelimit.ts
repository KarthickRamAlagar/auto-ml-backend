import type { Env } from "../env";
import { HttpError } from "./http";

const stub = (env: Env, key: string) => env.LIMITER.get(env.LIMITER.idFromName(key));

/** Count one hit; throws 429 (with Retry-After) once the limit is passed. */
export async function limit(env: Env, key: string, max: number, windowSec: number, persist = false, what = "requests"): Promise<void> {
  const r = await stub(env, key).hit(max, windowSec, persist);
  if (!r.ok) {
    throw new HttpError(429, { message: `Too many ${what}. Try again in ${fmtWait(r.retryAfter)}.`, code: "rate_limited", retry_after: r.retryAfter }, {
      "Retry-After": String(r.retryAfter),
    });
  }
}

/** Throw 429 if the key is already locked, without counting. */
export async function assertNotLocked(env: Env, key: string, max: number, what = "attempts"): Promise<void> {
  const r = await stub(env, key).peek(max, true);
  if (r.locked) {
    throw new HttpError(429, { message: `Too many ${what}. Try again in ${fmtWait(r.retryAfter)}.`, code: "locked", retry_after: r.retryAfter }, {
      "Retry-After": String(r.retryAfter),
    });
  }
}

export async function recordFailure(env: Env, key: string, max: number, windowSec: number): Promise<void> {
  await stub(env, key).hit(max, windowSec, true);
}

export async function clearKey(env: Env, key: string): Promise<void> {
  await stub(env, key).clear();
}

function fmtWait(sec: number): string {
  if (sec < 90) return `${sec} seconds`;
  return `${Math.ceil(sec / 60)} minutes`;
}
