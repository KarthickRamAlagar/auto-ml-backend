import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

interface Window {
  count: number;
  resetAt: number; // ms
}

/**
 * One Durable Object per rate-limit key (for example "login:alice@example.com"). A Durable Object runs one request
 * at a time, so the counter is exact even with hundreds of simultaneous callers, with no Redis needed.
 * `persist` keeps the window across restarts (login lock-outs); otherwise it lives in memory (cheap, per-request limits).
 */
export class RateLimiter extends DurableObject<Env> {
  private mem: Window | null = null;

  private async load(persist: boolean): Promise<Window | null> {
    return persist ? ((await this.ctx.storage.get<Window>("w")) ?? null) : this.mem;
  }

  private async save(w: Window, persist: boolean): Promise<void> {
    if (persist) {
      await this.ctx.storage.put("w", w);
      if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(w.resetAt + 1000);
    } else {
      this.mem = w;
    }
  }

  /** Count one attempt. ok=false once `limit` attempts happened inside the window. */
  async hit(limit: number, windowSec: number, persist = false): Promise<{ ok: boolean; remaining: number; retryAfter: number }> {
    const t = Date.now();
    let w = await this.load(persist);
    if (!w || t >= w.resetAt) w = { count: 0, resetAt: t + windowSec * 1000 };
    if (w.count >= limit) return { ok: false, remaining: 0, retryAfter: Math.max(1, Math.ceil((w.resetAt - t) / 1000)) };
    w.count += 1;
    await this.save(w, persist);
    return { ok: true, remaining: limit - w.count, retryAfter: 0 };
  }

  /** Read without counting (is this key already locked?). */
  async peek(limit: number, persist = false): Promise<{ locked: boolean; retryAfter: number }> {
    const t = Date.now();
    const w = await this.load(persist);
    if (!w || t >= w.resetAt || w.count < limit) return { locked: false, retryAfter: 0 };
    return { locked: true, retryAfter: Math.max(1, Math.ceil((w.resetAt - t) / 1000)) };
  }

  async clear(): Promise<void> {
    this.mem = null;
    await this.ctx.storage.deleteAll();
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
