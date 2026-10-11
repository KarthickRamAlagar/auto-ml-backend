import type { AuthUser, Config, Env } from "../env";
import { hmacHex } from "./crypto";
import { HttpError } from "./http";

/**
 * Identity the Worker vouches for. The Python engine runs in AUTH_MODE=gateway and accepts a request only when this
 * signature (HMAC-SHA256 with the shared GATEWAY_SECRET, 60-second window) is valid, so it cannot be called directly.
 */
export async function identityHeaders(env: Env, u: AuthUser): Promise<Record<string, string>> {
  const ts = String(Math.floor(Date.now() / 1000));
  const verified = u.verified ? "1" : "0";
  const admin = u.isAdmin ? "1" : "0";
  const sig = await hmacHex(env.GATEWAY_SECRET, `${ts}.${u.id}.${u.email}.${verified}.${admin}`);
  return { "X-Gateway-Uid": u.id, "X-Gateway-Email": u.email, "X-Gateway-Verified": verified, "X-Gateway-Admin": admin, "X-Gateway-Ts": ts, "X-Gateway-Sig": sig };
}

export async function engineFetch(env: Env, cfg: Config, u: AuthUser, path: string, init: RequestInit & { timeoutMs?: number } = {}): Promise<Response> {
  const viaBinding = !cfg.engineUrl && !!env.ML_SERVICE; // ENGINE_URL wins when set (local runs, other hosts)
  if (!viaBinding && !cfg.engineUrl) throw new HttpError(503, "The analysis engine is not configured.");
  const headers = new Headers(init.headers);
  for (const [k, v] of Object.entries(await identityHeaders(env, u))) headers.set(k, v);
  try {
    // service binding (private, no public hop) when deployed; plain HTTP to ENGINE_URL for local runs and other hosts
    const call = viaBinding ? (u: string, i: RequestInit) => env.ML_SERVICE!.fetch(u, i) : fetch;
    return await call(`${viaBinding ? "https://ml.internal" : cfg.engineUrl}${path}`, {
      ...init,
      headers,
      redirect: "manual",
      signal: init.timeoutMs ? AbortSignal.timeout(init.timeoutMs) : init.signal,
    });
  } catch (e) {
    const timeout = (e as Error)?.name === "TimeoutError";
    throw new HttpError(timeout ? 504 : 502, timeout ? "The analysis engine took too long to answer. Try again." : "The analysis engine is waking up or unreachable. Try again in a minute.");
  }
}
