// The Python engine's `Store` interface (backend/app/store.py), implemented over D1 (rows) and R2 (run archives).
// The engine calls this through the signed /internal/store endpoint; nothing here is reachable by a browser.
import type { Env } from "../env";
import { HttpError, now, parseJson } from "./http";

type Doc = Record<string, unknown>;
type Row = Record<string, unknown>;

const MAX_DOC_BYTES = 1_800_000; // D1 rows are limited to 2 MB
const USER_KNOWN = new Set(["uid", "email", "username", "contact", "email_verified", "created_at", "window_start", "free_used", "paid_used", "verified_spend", "reports_used", "paid_blocked"]);
const PAY_COLUMNS = ["id", "ref", "uid", "user_email", "kind", "job_id", "project_id", "amount", "currency", "breakdown", "status", "created_at", "claimed_at", "decided_at", "decided_by", "reminded_at", "reminders", "context"];

const str = (v: unknown, name: string): string => {
  if (typeof v !== "string" || !v || v.length > 200) throw new HttpError(400, `Invalid ${name}`);
  return v;
};
const numOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const int = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : d);
const json = (v: unknown): string => {
  const s = JSON.stringify(v ?? {});
  if (s.length > MAX_DOC_BYTES) throw new HttpError(413, "Document too large");
  return s;
};

// --------------------------------------------------------------------------- users
function userDoc(r: Row): Doc {
  return {
    ...parseJson<Doc>(r.extra as string, {}),
    uid: r.id,
    email: r.email,
    username: r.username,
    contact: r.contact ?? null,
    email_verified: r.email_verified === 1,
    created_at: r.created_at,
    window_start: r.window_start ?? null,
    free_used: r.free_used,
    paid_used: r.paid_used,
    verified_spend: r.verified_spend,
    reports_used: r.reports_used,
    paid_blocked: r.paid_blocked === 1,
  };
}

// --------------------------------------------------------------------------- payments
function payDoc(r: Row): Doc {
  const { id, ref, user_id, user_email, kind, job_id, project_id, amount, currency, breakdown, status, created_at, claimed_at, decided_at, decided_by, reminded_at, reminders, context, extra, state } = r;
  return {
    ...parseJson<Doc>(extra as string, {}),
    id, ref, uid: user_id, user_email, kind, job_id, project_id, amount, currency, status, state, created_at, claimed_at, decided_at, decided_by, reminded_at, reminders,
    breakdown: parseJson(breakdown as string, {}),
    context: parseJson(context as string, {}),
  };
}

function payParams(d: Doc): { cols: Record<string, unknown>; extra: Doc } {
  const cols: Record<string, unknown> = {};
  const extra: Doc = {};
  for (const [k, v] of Object.entries(d)) {
    if (k === "state") continue; // generated column
    if (PAY_COLUMNS.includes(k)) cols[k === "uid" ? "user_id" : k] = k === "breakdown" || k === "context" ? json(v) : v === undefined ? null : v;
    else extra[k] = v;
  }
  return { cols, extra };
}

// --------------------------------------------------------------------------- archives (R2, gzip)
async function gzip(text: string): Promise<ArrayBuffer> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Response(stream).arrayBuffer();
}
async function gunzip(buf: ArrayBuffer): Promise<string> {
  return new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
}

type Handler = (env: Env, a: unknown[]) => Promise<unknown>;

const H: Record<string, Handler> = {
  // ---- users
  async get_user(env, [uid]) {
    const r = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(str(uid, "uid")).first<Row>();
    return r ? userDoc(r) : null;
  },
  async put_user(env, [uid, data]) {
    const d = (data ?? {}) as Doc;
    const extra: Doc = {};
    for (const [k, v] of Object.entries(d)) if (!USER_KNOWN.has(k)) extra[k] = v;
    // The engine may only change usage counters; identity (email, username, password) stays with the Worker.
    await env.DB.prepare(
      "UPDATE users SET window_start = ?, free_used = ?, paid_used = ?, verified_spend = ?, reports_used = ?, paid_blocked = ?, extra = ?, updated_at = ? WHERE id = ?",
    )
      .bind(numOrNull(d.window_start), Math.max(0, int(d.free_used)), Math.max(0, int(d.paid_used)), Math.max(0, Number(d.verified_spend) || 0), Math.max(0, int(d.reports_used)), d.paid_blocked ? 1 : 0, json(extra), now(), str(uid, "uid"))
      .run();
    return null;
  },
  async list_users(env) {
    const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC LIMIT 10000").all<Row>();
    return results.map(userDoc);
  },

  // ---- payments
  async create_payment(env, [data]) {
    const d = data as Doc;
    const { cols, extra } = payParams(d);
    cols.extra = json(extra);
    const keys = Object.keys(cols);
    await env.DB.prepare(`INSERT INTO payments (${keys.join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`)
      .bind(...keys.map((k) => cols[k]))
      .run();
    return null;
  },
  async get_payment(env, [pid]) {
    const r = await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(str(pid, "id")).first<Row>();
    return r ? payDoc(r) : null;
  },
  async update_payment(env, [pid, patch]) {
    const id = str(pid, "id");
    const cur = await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(id).first<Row>();
    if (!cur) return null;
    const { cols, extra } = payParams((patch ?? {}) as Doc);
    delete cols.id;
    delete cols.user_id; // a payment never changes owner
    const mergedExtra = { ...parseJson<Doc>(cur.extra as string, {}), ...extra };
    cols.extra = json(mergedExtra);
    const keys = Object.keys(cols);
    await env.DB.prepare(`UPDATE payments SET ${keys.map((k) => `${k} = ?`).join(", ")} WHERE id = ?`)
      .bind(...keys.map((k) => cols[k]), id)
      .run();
    const r = await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(id).first<Row>();
    return r ? payDoc(r) : null;
  },
  async list_payments(env, [status, uid]) {
    const where: string[] = [];
    const binds: unknown[] = [];
    if (typeof status === "string" && status) { where.push("status = ?"); binds.push(status); }
    if (typeof uid === "string" && uid) { where.push("user_id = ?"); binds.push(uid); }
    const sql = `SELECT * FROM payments${where.length ? " WHERE " + where.join(" AND ") : ""} ORDER BY created_at DESC LIMIT 5000`;
    const { results } = await env.DB.prepare(sql).bind(...binds).all<Row>();
    return results.map(payDoc);
  },

  // ---- events, vip, feedback
  async add_event(env, [data]) {
    const d = data as Doc;
    await env.DB.prepare("INSERT INTO events (ts, uid, data) VALUES (?, ?, ?)").bind(numOrNull(d.ts) ?? now(), typeof d.uid === "string" ? d.uid : null, json(d)).run();
    return null;
  },
  async list_events(env, [since]) {
    const { results } = await env.DB.prepare("SELECT data FROM events WHERE ts >= ? ORDER BY ts ASC LIMIT 50000").bind(numOrNull(since) ?? 0).all<Row>();
    return results.map((r) => parseJson<Doc>(r.data as string, {}));
  },
  async get_vip(env) {
    const { results } = await env.DB.prepare("SELECT email FROM vip ORDER BY email").all<Row>();
    return results.map((r) => String(r.email).toLowerCase());
  },
  async add_vip(env, [email]) {
    await env.DB.prepare("INSERT OR IGNORE INTO vip (email, added_at) VALUES (?, ?)").bind(str(email, "email").toLowerCase(), now()).run();
    return null;
  },
  async remove_vip(env, [email]) {
    await env.DB.prepare("DELETE FROM vip WHERE email = ?").bind(str(email, "email").toLowerCase()).run();
    return null;
  },
  async add_feedback(env, [data]) {
    const d = data as Doc;
    await env.DB.prepare("INSERT INTO feedback (ts, uid, data) VALUES (?, ?, ?)").bind(numOrNull(d.ts) ?? now(), typeof d.uid === "string" ? d.uid : null, json(d)).run();
    return null;
  },
  async list_feedback(env, [limit]) {
    const n = Math.min(Math.max(int(limit, 100), 1), 1000);
    const { results } = await env.DB.prepare("SELECT data FROM feedback ORDER BY ts DESC LIMIT ?").bind(n).all<Row>();
    return results.map((r) => parseJson<Doc>(r.data as string, {}));
  },

  // ---- projects (chats) and groups
  async put_project(env, [pid, data]) {
    const d = data as Doc;
    const t = now();
    const created = numOrNull(d.created_at) ?? t;
    await env.DB.prepare(
      "INSERT INTO projects (id, user_id, group_id, created_at, updated_at, data) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET group_id = excluded.group_id, updated_at = excluded.updated_at, data = excluded.data WHERE projects.user_id = excluded.user_id",
    )
      .bind(str(pid, "id"), str(d.uid, "uid"), typeof d.group_id === "string" ? d.group_id : null, created, numOrNull(d.updated_at) ?? created, json(d))
      .run();
    return null;
  },
  async get_project(env, [pid]) {
    const r = await env.DB.prepare("SELECT data FROM projects WHERE id = ?").bind(str(pid, "id")).first<Row>();
    return r ? parseJson<Doc>(r.data as string, {}) : null;
  },
  async list_projects(env, [uid]) {
    const { results } = await env.DB.prepare("SELECT data FROM projects WHERE user_id = ? ORDER BY created_at DESC LIMIT 1000").bind(str(uid, "uid")).all<Row>();
    return results.map((r) => parseJson<Doc>(r.data as string, {}));
  },
  async delete_project(env, [pid]) {
    await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(str(pid, "id")).run();
    return null;
  },
  async list_projects_before(env, [ts]) {
    const { results } = await env.DB.prepare("SELECT data FROM projects WHERE updated_at < ? LIMIT 2000").bind(numOrNull(ts) ?? 0).all<Row>();
    return results.map((r) => parseJson<Doc>(r.data as string, {}));
  },
  async put_group(env, [gid, data]) {
    const d = data as Doc;
    await env.DB.prepare(
      "INSERT INTO groups (id, user_id, created_at, data) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data WHERE groups.user_id = excluded.user_id",
    )
      .bind(str(gid, "id"), str(d.uid, "uid"), numOrNull(d.created_at) ?? now(), json(d))
      .run();
    return null;
  },
  async get_group(env, [gid]) {
    const r = await env.DB.prepare("SELECT data FROM groups WHERE id = ?").bind(str(gid, "id")).first<Row>();
    return r ? parseJson<Doc>(r.data as string, {}) : null;
  },
  async list_groups(env, [uid]) {
    const { results } = await env.DB.prepare("SELECT data FROM groups WHERE user_id = ? ORDER BY created_at DESC LIMIT 200").bind(str(uid, "uid")).all<Row>();
    return results.map((r) => parseJson<Doc>(r.data as string, {}));
  },
  async delete_group(env, [gid]) {
    await env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(str(gid, "id")).run();
    return null;
  },

  // ---- archives (R2)
  async put_archive(env, [jobId, data]) {
    const id = str(jobId, "job_id");
    if (!/^[A-Za-z0-9_-]{4,64}$/.test(id)) throw new HttpError(400, "Invalid job id");
    const key = `archives/${id}.json.gz`;
    const body = await gzip(JSON.stringify(data ?? {}));
    await env.FILES.put(key, body, { httpMetadata: { contentType: "application/json", contentEncoding: "gzip" } });
    const uid = typeof (data as Doc)?.uid === "string" ? ((data as Doc).uid as string) : null;
    await env.DB.prepare("INSERT INTO archives (job_id, user_id, r2_key, size, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(job_id) DO UPDATE SET size = excluded.size")
      .bind(id, uid, key, body.byteLength, now())
      .run();
    return null;
  },
  async get_archive(env, [jobId]) {
    const id = str(jobId, "job_id");
    const obj = await env.FILES.get(`archives/${id}.json.gz`);
    if (!obj) return null;
    return JSON.parse(await gunzip(await obj.arrayBuffer()));
  },
  async delete_archive(env, [jobId]) {
    const id = str(jobId, "job_id");
    await env.FILES.delete(`archives/${id}.json.gz`);
    await env.DB.prepare("DELETE FROM archives WHERE job_id = ?").bind(id).run();
    return null;
  },
};

export const STORE_OPS = Object.keys(H);

export async function runStoreOp(env: Env, op: string, args: unknown[]): Promise<unknown> {
  const h = Object.hasOwn(H, op) ? H[op] : undefined;
  if (!h) throw new HttpError(400, `Unknown store operation: ${op}`);
  try {
    return await h(env, args);
  } catch (e) {
    if (e instanceof HttpError) throw e;
    const msg = String((e as Error)?.message ?? e);
    if (/UNIQUE constraint failed/i.test(msg)) throw new HttpError(409, "Already exists");
    if (/FOREIGN KEY constraint failed/i.test(msg)) throw new HttpError(404, "Owner not found");
    throw e;
  }
}
