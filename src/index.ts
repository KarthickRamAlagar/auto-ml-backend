import { handleMailBatch, type Mail } from "./lib/mail";
import { Hono } from "hono";
import type { AppEnv } from "./env";
import { config } from "./env";
import { HttpError } from "./lib/http";
import { apiRateLimit, requireUser } from "./middleware/auth";
import { apiHeaders, sameSiteOnly } from "./middleware/security";
import { auth } from "./routes/auth";
import { files } from "./routes/files";
import { internal } from "./routes/internal";
import { me } from "./routes/me";
import { proxyToEngine } from "./routes/proxy";
import { cleanup } from "./scheduled";
import { engineFetch } from "./lib/engine";

export { RateLimiter } from "./durable/rateLimiter";

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  c.set("reqId", crypto.randomUUID());
  c.set("ip", c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "0.0.0.0");
  c.set("user", null);
  await next();
});

app.onError((err, c) => {
  if (err instanceof HttpError) {
    const body = typeof err.detail === "string" ? { detail: err.detail } : { detail: err.detail };
    return new Response(JSON.stringify(body), { status: err.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...err.headers } });
  }
  console.error(`[${c.get("reqId")}] unhandled`, err instanceof Error ? `${err.name}: ${err.message}` : String(err));
  return c.json({ detail: "Something went wrong on our side. Please try again." }, 500);
});

// ---- the engine's state API (signed; not for browsers)
app.route("/internal", internal);

// ---- public API
app.use("/api/*", apiHeaders);
app.use("/api/*", sameSiteOnly);

app.get("/api/health", async (c) => {
  const cfg = config(c.env);
  const body: Record<string, unknown> = { ok: true, env: cfg.isProd ? "production" : c.env.APP_ENV, auth: "worker", google: Boolean(cfg.googleClientId) };
  if (c.req.query("deep") === "1") {
    try {
      const viaBinding = !cfg.engineUrl && !!c.env.ML_SERVICE;
      const url = viaBinding ? "https://ml.internal/api/health" : `${cfg.engineUrl}/api/health`;
      const r = await (viaBinding ? c.env.ML_SERVICE!.fetch(url, { signal: AbortSignal.timeout(8000) }) : fetch(url, { signal: AbortSignal.timeout(8000) }));
      body.engine = r.ok ? ((await r.json()) as Record<string, unknown>) : { ok: false, status: r.status };
    } catch {
      body.engine = { ok: false };
    }
  }
  return c.json(body);
});

// public config the sign-in page needs (no secrets)
app.get("/api/auth/config", (c) => c.json({ google_client_id: config(c.env).googleClientId || null }));

app.route("/api/auth", auth);

app.use("/api/*", requireUser);
app.use("/api/*", apiRateLimit);

app.route("/api", me);
app.route("/api", files);
app.all("/api/*", (c) => proxyToEngine(c));

app.notFound((c) => c.json({ detail: "Not found." }, 404));

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledController, env: AppEnv["Bindings"], ctx: ExecutionContext) {
    if (event.cron === "*/10 * * * *") {
      // keep-warm: free ML hosts sleep when idle; one tiny request every 10 minutes keeps it awake (KEEP_WARM=0 turns it off)
      const url = config(env).engineUrl;
      if (url && env.KEEP_WARM !== "0") ctx.waitUntil(fetch(`${url}/api/health`, { signal: AbortSignal.timeout(20000) }).then(() => undefined, () => undefined));
      return;
    }
    ctx.waitUntil(cleanup(env).then((r) => console.log("cleanup", JSON.stringify(r))));
  },
  async queue(batch: MessageBatch<unknown>, env: AppEnv["Bindings"]) {
    await handleMailBatch(batch as MessageBatch<Mail>, env);
  },
} satisfies ExportedHandler<AppEnv["Bindings"]>;

void engineFetch;
