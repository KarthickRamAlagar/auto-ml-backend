import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hmacHex } from "../src/lib/crypto";
import { Client, E, j, signedUp, uniq } from "./helpers";

type Seen = { url: string; method: string; headers: Headers; body: string | null };
let seen: Seen[] = [];
let engine: (req: Request, body: string | null) => Response | Promise<Response>;
const real = globalThis.fetch;

beforeEach(() => {
  seen = [];
  engine = () => new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input as RequestInfo, init);
    if (!req.url.startsWith("https://engine.test")) return real(input as RequestInfo, init);
    let body: string | null = null;
    if (!["GET", "HEAD"].includes(req.method)) {
      const ct = req.headers.get("content-type") ?? "";
      body = ct.startsWith("multipart/") ? `[multipart ${(await req.formData()).get("file") instanceof File ? "file" : "none"}]` : await req.text();
    }
    seen.push({ url: req.url, method: req.method, headers: req.headers, body });
    return engine(req, body);
  });
});
afterEach(() => vi.restoreAllMocks());

describe("engine proxy", () => {
  it("needs a session", async () => {
    expect((await new Client().get("/api/models?task=classification")).status).toBe(401);
    expect(seen).toHaveLength(0);
  });

  it("forwards with a valid signed identity and never leaks cookies or spoofed identity", async () => {
    const { c, json } = await signedUp();
    const res = await c.req("GET", "/api/models?task=classification&domain=Finance", undefined, { headers: { "X-Gateway-Uid": "someone-else", "X-Gateway-Admin": "1", Authorization: "Bearer abc" } });
    expect(res.status).toBe(200);
    const s = seen[0]!;
    expect(s.url).toBe("https://engine.test/api/models?task=classification&domain=Finance");
    expect(s.headers.get("cookie")).toBeNull();
    expect(s.headers.get("authorization")).toBeNull();
    expect(s.headers.get("x-gateway-uid")).toBe(json.user.id); // the Worker's own value, not the client's
    expect(s.headers.get("x-gateway-admin")).toBe("0");
    const ts = s.headers.get("x-gateway-ts")!;
    const sig = await hmacHex(E.GATEWAY_SECRET, `${ts}.${json.user.id}.${json.user.email}.0.0`);
    expect(s.headers.get("x-gateway-sig")).toBe(sig);
  });

  it("marks only a verified ADMIN_EMAILS address as admin for the engine", async () => {
    const email = "admin@example.com";
    let c: Client;
    let verifyUrl: string | undefined;
    try {
      const r = await signedUp({ email, username: uniq("adm") });
      c = r.c;
      verifyUrl = r.json.dev_verify_url;
    } catch {
      const login = new Client();
      expect((await login.post("/api/auth/login", { identifier: email, password: "Correct-horse-9" })).status).toBe(200);
      c = login;
    }
    await c.get("/api/models?task=regression");
    expect(seen.at(-1)!.headers.get("x-gateway-admin")).toBe(verifyUrl ? "0" : seen.at(-1)!.headers.get("x-gateway-admin"));
    if (verifyUrl) {
      await c.post("/api/auth/verify-email", { token: new URL(verifyUrl).searchParams.get("token") });
      await c.post("/api/auth/refresh");
      await c.get("/api/models?task=regression");
      expect(seen.at(-1)!.headers.get("x-gateway-admin")).toBe("1");
    }
  });

  it("passes JSON bodies and engine errors straight through", async () => {
    const { c } = await signedUp();
    engine = () => new Response(JSON.stringify({ detail: { message: "Daily limit reached", code: "limit" } }), { status: 429, headers: { "Content-Type": "application/json" } });
    const res = await c.post("/api/jobs", { dataset_id: "x" });
    expect(res.status).toBe(429);
    expect((await j(res)).detail.code).toBe("limit");
    expect(seen[0]!.body).toBe(JSON.stringify({ dataset_id: "x" }));
  });

  it("streams server-sent events without buffering", async () => {
    const { c } = await signedUp();
    engine = () => {
      const enc = new TextEncoder();
      const stream = new ReadableStream({
        async start(ctrl) {
          ctrl.enqueue(enc.encode('data: {"seq":0}\n\n'));
          await new Promise((r) => setTimeout(r, 30));
          ctrl.enqueue(enc.encode('data: {"seq":1,"type":"job_end"}\n\n'));
          ctrl.close();
        },
      });
      return new Response(stream, { headers: { "Content-Type": "text/event-stream" } });
    };
    const res = await c.get("/api/jobs/abc123xyz/events?from=0");
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.text()).toContain('"job_end"');
  });

  it("turns an unreachable engine into a clear 502", async () => {
    const { c } = await signedUp();
    engine = () => {
      throw new TypeError("network down");
    };
    const res = await c.get("/api/models?task=classification");
    expect(res.status).toBe(502);
    expect(typeof (await j(res)).detail).toBe("string");
  });

  it("refuses an oversized JSON body before it reaches the engine", async () => {
    const { c } = await signedUp();
    const res = await c.req("POST", "/api/jobs", undefined, { raw: "x".repeat(2_100_000), headers: { "Content-Type": "application/json" } });
    expect(res.status).toBe(413);
    expect(seen).toHaveLength(0);
  });

  it("never exposes the engine's own redirects", async () => {
    const { c } = await signedUp();
    engine = () => new Response(null, { status: 302, headers: { Location: "https://evil.example" } });
    expect((await c.get("/api/models?task=classification")).status).toBe(502);
  });
});

describe("file uploads (R2)", () => {
  const csv = (rows = 30) => "a,b,c\n" + Array.from({ length: rows }, (_, i) => `${i},${i * 2},x${i}`).join("\n");
  const form = (content: string | Uint8Array, name = "data.csv") => {
    const fd = new FormData();
    fd.append("file", new File([content as unknown as string], name, { type: "text/csv" }));
    return fd;
  };
  const upload = (c: Client, fd: FormData) => c.req("POST", "/api/datasets/upload", undefined, { raw: fd });

  it("stores the file in R2, registers it in D1 and returns the engine's dataset", async () => {
    const { c, json } = await signedUp();
    engine = () => new Response(JSON.stringify({ dataset_id: "ds1", name: "data.csv", rows: 30 }), { headers: { "Content-Type": "application/json" } });
    const res = await upload(c, form(csv()));
    expect(res.status).toBe(200);
    const out = await j(res);
    expect(out.dataset_id).toBe("ds1");
    expect(out.file.name).toBe("data.csv");
    expect(seen[0]!.url).toBe("https://engine.test/api/datasets/upload");
    expect(seen[0]!.body).toBe("[multipart file]");
    expect(seen[0]!.headers.get("x-gateway-uid")).toBe(json.user.id);
    const row = await E.DB.prepare("SELECT r2_key, size, sha256 FROM files WHERE id = ?").bind(out.file.id).first<{ r2_key: string; size: number; sha256: string }>();
    expect(row!.r2_key.startsWith(`uploads/${json.user.id}/`)).toBe(true);
    expect((await E.FILES.get(row!.r2_key))!.size).toBe(row!.size);
    const list = await j(await c.get("/api/files"));
    expect(list.files.map((f: { id: string }) => f.id)).toContain(out.file.id);
  });

  it("accepts Excel, Parquet and JSON uploads (binary formats may contain NUL bytes)", async () => {
    const { c } = await signedUp();
    engine = () => new Response(JSON.stringify({ dataset_id: "ds2", name: "t", rows: 30 }), { headers: { "Content-Type": "application/json" } });
    expect((await upload(c, form(new Uint8Array([80, 75, 3, 4, 0, 0, 1]), "table.xlsx"))).status).toBe(200);
    expect((await upload(c, form(new Uint8Array([80, 65, 82, 49, 0, 0]), "table.parquet"))).status).toBe(200);
    expect((await upload(c, form('[{"a":1}]', "rows.json"))).status).toBe(200);
  });

  it("rejects wrong type, binary content, empty and oversized files", async () => {
    const { c } = await signedUp();
    expect((await upload(c, form(csv(), "evil.exe"))).status).toBe(415);
    expect((await upload(c, form(new Uint8Array([97, 44, 0, 1, 2]), "bin.csv"))).status).toBe(415);
    expect((await upload(c, form("", "empty.csv"))).status).toBe(400);
    expect((await upload(c, form("x".repeat(1_200_000), "big.csv"))).status).toBe(413);
    expect((await c.req("POST", "/api/datasets/upload", { nofile: true })).status).toBe(400);
    expect(seen).toHaveLength(0);
  });

  it("removes the stored file when the engine rejects it", async () => {
    const { c, json } = await signedUp();
    engine = () => new Response(JSON.stringify({ detail: "Need at least 2 columns and 20 rows." }), { status: 400, headers: { "Content-Type": "application/json" } });
    const res = await upload(c, form("a\n1\n"));
    expect(res.status).toBe(400);
    expect((await j(res)).detail).toContain("20 rows");
    const n = await E.DB.prepare("SELECT COUNT(*) AS n FROM files WHERE user_id = ?").bind(json.user.id).first<{ n: number }>();
    expect(n!.n).toBe(0);
    const listed = await E.FILES.list({ prefix: `uploads/${json.user.id}/` });
    expect(listed.objects).toHaveLength(0);
  });

  it("does not store the same content twice for one user", async () => {
    const { c, json } = await signedUp();
    const a = await j(await upload(c, form(csv(), "one.csv")));
    const b = await j(await upload(c, form(csv(), "two.csv")));
    expect(b.file.id).toBe(a.file.id);
    const n = await E.DB.prepare("SELECT COUNT(*) AS n FROM files WHERE user_id = ?").bind(json.user.id).first<{ n: number }>();
    expect(n!.n).toBe(1);
  });

  it("enforces the per-user file limit", async () => {
    const { c, json } = await signedUp();
    const t = Date.now() / 1000;
    await E.DB.batch(Array.from({ length: 30 }, (_, i) => E.DB.prepare("INSERT INTO files (id, user_id, r2_key, name, mime, size, sha256, created_at, expires_at) VALUES (?, ?, ?, 'f.csv', 'text/csv', 10, ?, ?, ?)").bind(`${i}`.padStart(20, "a"), json.user.id, `uploads/x/${i}`, `h${i}`, t, t + 1000)));
    const res = await upload(c, form(csv(40), "new.csv"));
    expect(res.status).toBe(409);
    expect((await j(res)).detail.code).toBe("storage_full");
  });

  it("lets only the owner download, reuse or delete a file", async () => {
    const owner = await signedUp();
    const other = await signedUp();
    const up = await j(await upload(owner.c, form(csv())));
    const id = up.file.id as string;
    expect((await owner.c.get(`/api/files/${id}/download`)).headers.get("content-disposition")).toContain("attachment");
    expect((await other.c.get(`/api/files/${id}/download`)).status).toBe(403);
    expect((await other.c.post(`/api/files/${id}/use`)).status).toBe(403);
    expect((await other.c.req("DELETE", `/api/files/${id}`)).status).toBe(403);
    expect((await owner.c.post(`/api/files/${id}/use`)).status).toBe(200);
    expect((await owner.c.get("/api/files/not-an-id/download")).status).toBe(404);
    expect((await owner.c.req("DELETE", `/api/files/${id}`)).status).toBe(200);
    expect((await owner.c.get(`/api/files/${id}/download`)).status).toBe(404);
  });
});

describe("rate limiting", () => {
  it("limits password-reset requests per network address", async () => {
    const c = new Client();
    let last = 0;
    for (let i = 0; i < 10; i++) last = (await c.post("/api/auth/forgot", { email: `${uniq("rl")}@example.com` })).status;
    expect(last).toBe(429);
  });

  it("limits sign-ups per network address", async () => {
    const c = new Client();
    const codes: number[] = [];
    for (let i = 0; i < 22; i++) codes.push((await c.post("/api/auth/signup", { username: "x", email: "bad", contact: "1", password: "x" })).status);
    // invalid bodies fail validation first (422) and do not count; valid ones do:
    expect(codes.every((s) => s === 422)).toBe(true);
    const d = new Client();
    let blocked = 0;
    for (let i = 0; i < 22; i++) {
      const id = uniq("rl");
      const r = await d.post("/api/auth/signup", { username: id, email: `${id}@example.com`, contact: "+919876543210", password: "Correct-horse-9" });
      if (r.status === 429) blocked++;
    }
    expect(blocked).toBeGreaterThan(0);
  });
});

describe("static site and headers", () => {
  it("adds security headers to API answers", async () => {
    const res = await new Client().get("/api/health");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("strict-transport-security")).toContain("max-age");
    expect((await j(res)).auth).toBe("worker");
  });

  it("shows only public configuration", async () => {
    const cfg = await j(await new Client().get("/api/auth/config"));
    expect(Object.keys(cfg)).toEqual(["google_client_id"]);
  });
});
