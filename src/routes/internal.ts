import { Hono } from "hono";
import { z } from "zod";
import type { AppEnv } from "../env";
import { hmacHex, safeEqual, sha256Hex } from "../lib/crypto";
import { HttpError } from "../lib/http";
import { runStoreOp } from "../lib/storeOps";

/**
 * State API for the Python engine. Not a browser route: every call carries
 *   X-Store-Ts   unix seconds (must be within 60 s)
 *   X-Store-Sig  HMAC-SHA256(STORE_SECRET, ts + "." + sha256(body))
 * so only a holder of STORE_SECRET can read or write users, payments, chats and archives.
 */
export const internal = new Hono<AppEnv>();

const Body = z.object({ op: z.string().min(1).max(40), args: z.array(z.unknown()).max(4) });
const MAX_BODY = 6_000_000; // run archives are the largest documents

internal.post("/store", async (c) => {
  const ts = c.req.header("x-store-ts") ?? "";
  const sig = c.req.header("x-store-sig") ?? "";
  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!/^\d{10}$/.test(ts) || age > 60) throw new HttpError(401, "Stale or missing timestamp.");
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared > MAX_BODY) throw new HttpError(413, "Body too large.");
  const raw = await c.req.text();
  if (raw.length > MAX_BODY) throw new HttpError(413, "Body too large.");
  const expected = await hmacHex(c.env.STORE_SECRET, `${ts}.${await sha256Hex(raw)}`);
  if (!sig || !(await safeEqual(sig, expected))) throw new HttpError(401, "Bad signature.");

  let parsed: z.infer<typeof Body>;
  try {
    parsed = Body.parse(JSON.parse(raw));
  } catch {
    throw new HttpError(400, "Bad request body.");
  }
  const result = await runStoreOp(c.env, parsed.op, parsed.args);
  return c.json({ result: result ?? null });
});
