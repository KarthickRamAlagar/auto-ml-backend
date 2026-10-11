// Types for `env` and `exports` from "cloudflare:workers" inside the test runtime.
declare namespace Cloudflare {
  interface Env extends import("../src/env").Env {}
  interface GlobalProps {
    mainModule: typeof import("../src/index");
    durableNamespaces: "RateLimiter";
  }
}
