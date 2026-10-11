import { env, exports } from "cloudflare:workers";
import type { Env } from "../src/env";

export const E = env as unknown as Env;
export const ORIGIN = "https://app.test";

let n = 0;
export const uniq = (p = "u") => `${p}${Date.now().toString(36)}${(n++).toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;

/** A tiny browser: keeps cookies between calls and always sends a same-site Origin. */
export class Client {
  jar = new Map<string, string>();
  ip = `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

  async req(method: string, path: string, body?: unknown, init: { origin?: string | null; headers?: Record<string, string>; raw?: BodyInit } = {}): Promise<Response> {
    const headers: Record<string, string> = { "cf-connecting-ip": this.ip, ...(init.headers ?? {}) };
    if (init.origin !== null) headers.Origin = init.origin ?? ORIGIN;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    if (cookie) headers.Cookie = cookie;
    const res = await exports.default.fetch(new Request(`${ORIGIN}${path}`, { method, headers, body: init.raw ?? (body === undefined ? undefined : JSON.stringify(body)) }));
    for (const sc of res.headers.getSetCookie()) {
      const [pair] = sc.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i);
      const value = pair!.slice(i + 1);
      if (/Max-Age=0/i.test(sc) || value === "") this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return res;
  }
  get = (p: string) => this.req("GET", p);
  post = (p: string, b?: unknown, init?: Parameters<Client["req"]>[3]) => this.req("POST", p, b ?? {}, init);
}

export const validSignup = (over: Record<string, unknown> = {}) => {
  const id = uniq("user");
  return { username: id, email: `${id}@example.com`, contact: "+91 98765 43210", password: "Correct-horse-9", ...over };
};

export async function signedUp(over: Record<string, unknown> = {}) {
  const c = new Client();
  const body = validSignup(over);
  const res = await c.post("/api/auth/signup", body);
  if (res.status !== 201) throw new Error(`signup failed ${res.status} ${await res.text()}`);
  return { c, body, json: (await res.json()) as { user: { id: string; email: string; username: string }; dev_verify_url?: string } };
}

export const j = async <T = Record<string, any>>(r: Response): Promise<T> => (await r.json()) as T; // eslint-disable-line @typescript-eslint/no-explicit-any
