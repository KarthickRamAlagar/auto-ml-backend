import type { Env } from "./env";
import { now } from "./lib/http";

/** Daily housekeeping: expired uploads, finished sessions and one-time links, old audit rows. */
export async function cleanup(env: Env): Promise<Record<string, number>> {
  const t = now();
  const out: Record<string, number> = {};

  const { results: files } = await env.DB.prepare("SELECT id, r2_key FROM files WHERE expires_at <= ? LIMIT 1000").bind(t).all<{ id: string; r2_key: string }>();
  for (let i = 0; i < files.length; i += 100) {
    const chunk = files.slice(i, i + 100);
    await env.FILES.delete(chunk.map((f) => f.r2_key));
    await env.DB.batch(chunk.map((f) => env.DB.prepare("DELETE FROM files WHERE id = ?").bind(f.id)));
  }
  out.files = files.length;

  out.sessions = (await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ? OR (revoked_at IS NOT NULL AND revoked_at <= ?)").bind(t, t - 7 * 86400).run()).meta.changes ?? 0;
  out.tokens = (await env.DB.prepare("DELETE FROM auth_tokens WHERE expires_at <= ? OR used_at IS NOT NULL").bind(t - 86400).run()).meta.changes ?? 0;
  out.audit = (await env.DB.prepare("DELETE FROM audit_log WHERE ts <= ?").bind(t - 180 * 86400).run()).meta.changes ?? 0;

  // archives whose chat no longer exists (the engine's own retention loop removes them too; this is the safety net)
  const { results: orphan } = await env.DB.prepare("SELECT job_id, r2_key FROM archives WHERE created_at <= ? LIMIT 500").bind(t - 40 * 86400).all<{ job_id: string; r2_key: string }>();
  for (let i = 0; i < orphan.length; i += 100) {
    const chunk = orphan.slice(i, i + 100);
    await env.FILES.delete(chunk.map((a) => a.r2_key));
    await env.DB.batch(chunk.map((a) => env.DB.prepare("DELETE FROM archives WHERE job_id = ?").bind(a.job_id)));
  }
  out.archives = orphan.length;
  return out;
}
