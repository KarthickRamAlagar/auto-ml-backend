import type { Context } from "hono";
import type { AppEnv } from "../env";
import { config } from "../env";
import { engineFetch } from "../lib/engine";
import { HttpError } from "../lib/http";

const FORWARD_REQ = ["content-type", "accept", "accept-language", "if-none-match"];
const MAX_JSON_BODY = 2_000_000; // uploads go through the dedicated route, so everything else is small
const STREAM = /^\/api\/jobs\/[a-z0-9]+\/events$/;
const SLOW = /^\/api\/admin\/(llm|youtube)\/test$/;

/** Forward every other /api call to the Python engine with a signed identity. Streaming (SSE) responses pass straight through. */
export async function proxyToEngine(c: Context<AppEnv>): Promise<Response> {
  const cfg = config(c.env);
  const url = new URL(c.req.url);
  const method = c.req.method;
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared > MAX_JSON_BODY) throw new HttpError(413, "Request body is too large.");

  const headers = new Headers();
  for (const h of FORWARD_REQ) {
    const v = c.req.header(h);
    if (v) headers.set(h, v);
  }
  let body: BodyInit | undefined;
  if (!["GET", "HEAD"].includes(method)) {
    const buf = await c.req.arrayBuffer();
    if (buf.byteLength > MAX_JSON_BODY) throw new HttpError(413, "Request body is too large.");
    body = buf;
  }
  const stream = STREAM.test(url.pathname);
  const res = await engineFetch(c.env, cfg, c.get("user")!, `${url.pathname}${url.search}`, {
    method,
    headers,
    body,
    timeoutMs: stream ? undefined : SLOW.test(url.pathname) ? 175_000 : 100_000,
    signal: stream ? c.req.raw.signal : undefined,
  });
  if (res.status >= 300 && res.status < 400) throw new HttpError(502, "Unexpected redirect from the analysis engine.");

  const out = new Headers();
  for (const h of ["content-type", "retry-after", "content-disposition"]) {
    const v = res.headers.get(h);
    if (v) out.set(h, v);
  }
  if (stream) {
    out.set("Cache-Control", "no-store");
    out.set("X-Accel-Buffering", "no");
  }
  return new Response(res.body, { status: res.status, headers: out });
}
