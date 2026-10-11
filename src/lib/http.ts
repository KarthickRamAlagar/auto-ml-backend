export class HttpError extends Error {
  constructor(
    public status: number,
    public detail: string | Record<string, unknown>,
    public headers: Record<string, string> = {},
  ) {
    super(typeof detail === "string" ? detail : String(detail.message ?? "error"));
  }
}

export const bad = (msg: string, status = 400) => new HttpError(status, msg);
export const unauthorized = (msg = "Please sign in.") => new HttpError(401, msg);
export const forbidden = (msg = "Not allowed.") => new HttpError(403, msg);
export const notFound = (msg = "Not found.") => new HttpError(404, msg);

export const now = () => Date.now() / 1000;

export function parseJson<T>(text: string | null | undefined, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

export function cookie(
  name: string,
  value: string,
  opts: { maxAge?: number; path?: string; secure: boolean; sameSite?: "Strict" | "Lax" },
): string {
  const parts = [`${name}=${value}`, `Path=${opts.path ?? "/"}`, "HttpOnly", `SameSite=${opts.sameSite ?? "Lax"}`];
  if (opts.secure) parts.push("Secure");
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  return parts.join("; ");
}

export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
