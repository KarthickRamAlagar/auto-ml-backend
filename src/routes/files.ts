import { Hono, type Context } from "hono";
import type { AppEnv } from "../env";
import { config } from "../env";
import { hex, randomId } from "../lib/crypto";
import { engineFetch } from "../lib/engine";
import { HttpError, bad, forbidden, notFound, now } from "../lib/http";
import { audit } from "../lib/session";

export const files = new Hono<AppEnv>();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Ctx = Context<AppEnv, any, any>;

const MAX_FILES = 30;
const MAX_TOTAL_BYTES = 300 * 1024 * 1024;
const ID = /^[a-f0-9]{20}$/;
const EXT = /\.(csv|tsv|txt|xlsx|xlsm|parquet|json|jsonl|ndjson)$/i;
const BINARY_EXT = /\.(xlsx|xlsm|parquet)$/i; // binary formats legitimately contain NUL bytes
const MIME: Record<string, string> = {
  csv: "text/csv", tsv: "text/tab-separated-values", txt: "text/plain", json: "application/json", jsonl: "application/x-ndjson",
  ndjson: "application/x-ndjson", parquet: "application/vnd.apache.parquet", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  xlsm: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};
const mimeOf = (name: string) => MIME[(name.split(".").pop() ?? "").toLowerCase()] ?? "application/octet-stream";

interface FileRow {
  id: string;
  user_id: string;
  r2_key: string;
  name: string;
  mime: string;
  size: number;
  sha256: string;
  created_at: number;
  expires_at: number;
}

const view = (f: FileRow) => ({ id: f.id, name: f.name, size: f.size, mime: f.mime, created_at: f.created_at, expires_at: f.expires_at });

const safeName = (n: string) => n.replace(/[\u0000-\u001f\\/:*?"<>|]/g, "").replace(/\s+/g, " ").trim().slice(0, 80) || "dataset.csv";

/** Hand the bytes to the engine for parsing; whatever it answers (dataset summary or error) goes back to the browser. */
async function parseWithEngine(c: Ctx, name: string, bytes: ArrayBuffer): Promise<Response> {
  const fd = new FormData();
  fd.append("file", new File([bytes], name, { type: mimeOf(name) }));
  return engineFetch(c.env, config(c.env), c.get("user")!, "/api/datasets/upload", { method: "POST", body: fd, timeoutMs: 120_000 });
}

files.post("/datasets/upload", async (c) => {
  const cfg = config(c.env);
  const u = c.get("user")!;
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared > cfg.maxUploadBytes + 1_048_576) throw new HttpError(413, `File is larger than ${Math.round(cfg.maxUploadBytes / 1048576)} MB.`);

  let form: FormData;
  try {
    form = await c.req.formData();
  } catch {
    throw bad("Send the file as multipart form data.");
  }
  const file = form.get("file");
  if (!(file instanceof File)) throw bad("No file was uploaded.");
  if (!EXT.test(file.name)) throw bad("Upload a CSV, Excel (.xlsx), Parquet or JSON file.", 415);
  if (file.size === 0) throw bad("The file is empty.");
  if (file.size > cfg.maxUploadBytes) throw new HttpError(413, `File is larger than ${Math.round(cfg.maxUploadBytes / 1048576)} MB.`);

  const bytes = await file.arrayBuffer();
  if (!BINARY_EXT.test(file.name) && new Uint8Array(bytes, 0, Math.min(4096, bytes.byteLength)).includes(0)) throw bad("That does not look like a text file. Use .xlsx or .parquet for binary data.", 415);
  const name = safeName(file.name);
  const sha = hex(await crypto.subtle.digest("SHA-256", bytes));
  const t = now();

  const existing = await c.env.DB.prepare("SELECT * FROM files WHERE user_id = ? AND sha256 = ? AND expires_at > ?").bind(u.id, sha, t).first<FileRow>();
  let row = existing;
  if (!row) {
    const q = await c.env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM files WHERE user_id = ? AND expires_at > ?").bind(u.id, t).first<{ n: number; bytes: number }>();
    if ((q?.n ?? 0) >= MAX_FILES || (q?.bytes ?? 0) + bytes.byteLength > MAX_TOTAL_BYTES) {
      throw new HttpError(409, { message: "Your file storage is full. Delete an older file in Settings first.", code: "storage_full" });
    }
    const id = randomId();
    const key = `uploads/${u.id}/${id}`;
    await c.env.FILES.put(key, bytes, { httpMetadata: { contentType: mimeOf(name) }, customMetadata: { uid: u.id, name } });
    row = { id, user_id: u.id, r2_key: key, name, mime: mimeOf(name), size: bytes.byteLength, sha256: sha, created_at: t, expires_at: t + cfg.retentionDays * 86400 };
    await c.env.DB.prepare("INSERT INTO files (id, user_id, r2_key, name, mime, size, sha256, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(row.id, row.user_id, row.r2_key, row.name, row.mime, row.size, row.sha256, row.created_at, row.expires_at)
      .run();
  }

  const res = await parseWithEngine(c, name, bytes);
  if (!res.ok) {
    if (!existing) {
      await c.env.FILES.delete(row.r2_key); // do not keep a file the engine rejected
      await c.env.DB.prepare("DELETE FROM files WHERE id = ?").bind(row.id).run();
    }
    return new Response(res.body, { status: res.status, headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" } });
  }
  const out = (await res.json()) as Record<string, unknown>;
  return c.json({ ...out, file: view(row) });
});

files.get("/files", async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM files WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 100").bind(c.get("user")!.id, now()).all<FileRow>();
  return c.json({ files: results.map(view), limit: MAX_FILES });
});

async function own(c: Ctx, id: string): Promise<FileRow> {
  if (!ID.test(id)) throw notFound("File not found.");
  const f = await c.env.DB.prepare("SELECT * FROM files WHERE id = ? AND expires_at > ?").bind(id, now()).first<FileRow>();
  if (!f) throw notFound("File not found.");
  if (f.user_id !== c.get("user")!.id) throw forbidden("File not found."); // 403 vs 404 reveals nothing useful: ids are unguessable
  return f;
}

files.get("/files/:id/download", async (c) => {
  const f = await own(c, c.req.param("id"));
  const obj = await c.env.FILES.get(f.r2_key);
  if (!obj) throw notFound("File not found.");
  await audit(c.env, f.user_id, "file_download", f.id, c.get("ip"));
  return new Response(obj.body, {
    headers: {
      "Content-Type": f.mime || "application/octet-stream",
      "Content-Disposition": `attachment; filename="${f.name.replace(/"/g, "")}"`,
      "Content-Length": String(f.size),
    },
  });
});

/** Re-use a stored file without uploading it again. */
files.post("/files/:id/use", async (c) => {
  const f = await own(c, c.req.param("id"));
  const obj = await c.env.FILES.get(f.r2_key);
  if (!obj) throw notFound("File not found.");
  const res = await parseWithEngine(c, f.name, await obj.arrayBuffer());
  if (!res.ok) return new Response(res.body, { status: res.status, headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" } });
  return c.json({ ...((await res.json()) as Record<string, unknown>), file: view(f) });
});

files.delete("/files/:id", async (c) => {
  const f = await own(c, c.req.param("id"));
  await c.env.FILES.delete(f.r2_key);
  await c.env.DB.prepare("DELETE FROM files WHERE id = ?").bind(f.id).run();
  await audit(c.env, f.user_id, "file_delete", f.id, c.get("ip"));
  return c.json({ ok: true });
});
