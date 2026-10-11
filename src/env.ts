export interface Env {
  DB: D1Database;
  FILES: R2Bucket;
  CACHE: KVNamespace;
  /** App 3 (Python ML service Worker). When absent the Worker calls ENGINE_URL over HTTP. */
  ML_SERVICE?: Fetcher;
  MAIL_QUEUE?: Queue<import("./lib/mail").Mail>;
  API_LIMITER?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
  LIMITER: DurableObjectNamespace<import("./durable/rateLimiter").RateLimiter>;

  APP_ENV: string;
  PUBLIC_APP_URL: string;
  ENGINE_URL: string;
  ADMIN_EMAILS: string;
  GOOGLE_CLIENT_ID: string;
  RETENTION_DAYS: string;
  MAX_UPLOAD_MB: string;
  PBKDF2_ITERATIONS: string;
  MAIL_FROM: string;
  KEEP_WARM?: string;

  JWT_SECRET: string;
  PASSWORD_PEPPER: string;
  GATEWAY_SECRET: string;
  STORE_SECRET: string;
  RESEND_API_KEY?: string;
}

export interface Config {
  isProd: boolean;
  appUrl: string;
  engineUrl: string;
  adminEmails: Set<string>;
  googleClientId: string;
  retentionDays: number;
  maxUploadBytes: number;
  pbkdf2Iterations: number;
  mailFrom: string;
}

const num = (v: string | undefined, d: number) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : d;
};

export function config(env: Env): Config {
  return {
    isProd: env.APP_ENV === "production",
    appUrl: (env.PUBLIC_APP_URL || "").replace(/\/$/, ""),
    engineUrl: (env.ENGINE_URL || "").replace(/\/$/, ""),
    adminEmails: new Set((env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean)),
    googleClientId: env.GOOGLE_CLIENT_ID || "",
    retentionDays: num(env.RETENTION_DAYS, 15),
    maxUploadBytes: num(env.MAX_UPLOAD_MB, 25) * 1024 * 1024,
    pbkdf2Iterations: Math.min(num(env.PBKDF2_ITERATIONS, 100_000), 100_000), // Workers caps PBKDF2 at 100k
    mailFrom: env.MAIL_FROM || "Auto ML <onboarding@resend.dev>",
  };
}

export interface AuthUser {
  id: string;
  email: string;
  username: string;
  verified: boolean;
  isAdmin: boolean;
  sessionId: string;
}

export type AppEnv = { Bindings: Env; Variables: { user: AuthUser | null; reqId: string; ip: string } };
