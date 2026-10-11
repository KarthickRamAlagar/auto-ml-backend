import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.test.jsonc" },
        miniflare: {
          bindings: {
            APP_ENV: "test",
            PUBLIC_APP_URL: "https://app.test",
            ENGINE_URL: "https://engine.test",
            ADMIN_EMAILS: "admin@example.com",
            GOOGLE_CLIENT_ID: "test-client-id.apps.googleusercontent.com",
            PBKDF2_ITERATIONS: "1000",
            MAX_UPLOAD_MB: "1",
            JWT_SECRET: "test-jwt-secret-test-jwt-secret-test-jwt-secret",
            PASSWORD_PEPPER: "test-pepper-test-pepper-test-pepper",
            GATEWAY_SECRET: "test-gateway-secret-test-gateway-secret",
            STORE_SECRET: "test-store-secret-test-store-secret-xx",
            TEST_MIGRATIONS: migrations,
          },
        },
      }),
    ],
    test: { include: ["test/**/*.test.ts"], setupFiles: ["./test/setup.ts"], testTimeout: 20000 },
  };
});
