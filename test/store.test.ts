import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { hmacHex, sha256Hex } from "../src/lib/crypto";
import { E, ORIGIN, signedUp, uniq } from "./helpers";

async function call(op: string, args: unknown[], over: { skew?: number; sig?: string; ts?: string } = {}) {
  const body = JSON.stringify({ op, args });
  const ts = over.ts ?? String(Math.floor(Date.now() / 1000) + (over.skew ?? 0));
  const sig = over.sig ?? (await hmacHex(E.STORE_SECRET, `${ts}.${await sha256Hex(body)}`));
  return exports.default.fetch(new Request(`${ORIGIN}/internal/store`, { method: "POST", headers: { "Content-Type": "application/json", "X-Store-Ts": ts, "X-Store-Sig": sig }, body }));
}
const result = async (op: string, args: unknown[]) => {
  const r = await call(op, args);
  if (r.status !== 200) throw new Error(`${op} -> ${r.status} ${await r.text()}`);
  return ((await r.json()) as { result: any }).result; // eslint-disable-line @typescript-eslint/no-explicit-any
};

describe("signed state API", () => {
  it("refuses unsigned, wrongly signed and stale calls", async () => {
    expect((await call("get_vip", [], { sig: "00" })).status).toBe(401);
    expect((await call("get_vip", [], { skew: -120 })).status).toBe(401);
    expect((await call("get_vip", [], { skew: 120 })).status).toBe(401);
    const none = await exports.default.fetch(new Request(`${ORIGIN}/internal/store`, { method: "POST", body: JSON.stringify({ op: "get_vip", args: [] }) }));
    expect(none.status).toBe(401);
    // a signature for a different body must not validate this body
    const ts = String(Math.floor(Date.now() / 1000));
    const sigOfOther = await hmacHex(E.STORE_SECRET, `${ts}.${await sha256Hex(JSON.stringify({ op: "get_vip", args: [] }))}`);
    expect((await call("list_users", [], { sig: sigOfOther, ts })).status).toBe(401);
  });

  it("is not reachable by a browser session", async () => {
    const { c } = await signedUp();
    expect((await c.post("/internal/store", { op: "list_users", args: [] }, { headers: { "X-Store-Ts": "1", "X-Store-Sig": "x" } })).status).toBe(401);
  });

  it("rejects unknown operations", async () => {
    expect((await call("drop_everything", [])).status).toBe(400);
    expect((await call("constructor", [])).status).toBe(400);
    expect((await call("__proto__", [])).status).toBe(400);
  });

  it("stores usage counters and extra engine fields, but never identity", async () => {
    const { json } = await signedUp();
    const uid = json.user.id;
    const u = await result("get_user", [uid]);
    expect(u.uid).toBe(uid);
    expect(u.free_used).toBe(0);
    await result("put_user", [uid, { ...u, email: "attacker@example.com", free_used: 4, paid_used: 2, window_start: 123.5, verified_spend: 60, paid_blocked: true, note: "kept" }]);
    const after = await result("get_user", [uid]);
    expect(after).toMatchObject({ free_used: 4, paid_used: 2, window_start: 123.5, verified_spend: 60, paid_blocked: true, note: "kept" });
    expect(after.email).toBe(json.user.email); // unchanged
    expect(await result("get_user", ["f".repeat(20)])).toBeNull();
  });

  it("runs the payment workflow and exposes pending / completed state", async () => {
    const { json } = await signedUp();
    const uid = json.user.id;
    const id = uniq("pay");
    await result("create_payment", [{ id, ref: `AML-${id.slice(-5).toUpperCase()}`, uid, user_email: json.user.email, kind: "models", job_id: "job1", project_id: "p1", amount: 22, breakdown: { lines: [{ label: "x", amount: 22 }], total: 22 }, status: "created", created_at: 1000, claimed_at: null, decided_at: null, context: { domain: "Finance", models: ["a"] }, custom_flag: 1 }]);
    let p = await result("get_payment", [id]);
    expect(p).toMatchObject({ id, uid, amount: 22, status: "created", state: "pending", custom_flag: 1 });
    expect(p.breakdown.total).toBe(22);
    expect(p.context.domain).toBe("Finance");

    p = await result("update_payment", [id, { status: "claimed", claimed_at: 2000 }]);
    expect(p).toMatchObject({ status: "claimed", state: "pending", claimed_at: 2000, custom_flag: 1 });
    p = await result("update_payment", [id, { status: "approved", decided_at: 3000, decided_by: "admin@example.com", uid: "someone-else", id: "other" }]);
    expect(p).toMatchObject({ status: "approved", state: "completed", decided_by: "admin@example.com", uid, id });
    expect(await result("update_payment", ["0".repeat(20), { status: "claimed" }])).toBeNull();

    expect((await result("list_payments", [null, uid])).map((x: { id: string }) => x.id)).toEqual([id]);
    expect((await result("list_payments", ["approved", uid])).length).toBe(1);
    expect((await result("list_payments", ["rejected", uid])).length).toBe(0);
    expect((await result("list_payments", [null, "nobody"])).length).toBe(0);
  });

  it("the database refuses invalid payments", async () => {
    const { json } = await signedUp();
    const base = { id: uniq("pay"), ref: uniq("R"), uid: json.user.id, user_email: "a@b.co", kind: "models", amount: 5, status: "created", created_at: 1 };
    expect((await call("create_payment", [{ ...base, status: "paid" }])).status).toBeGreaterThanOrEqual(400);
    expect((await call("create_payment", [{ ...base, id: uniq("pay"), ref: uniq("R"), amount: -1 }])).status).toBeGreaterThanOrEqual(400);
    expect((await call("create_payment", [{ ...base, id: uniq("pay"), ref: uniq("R"), uid: "ghost-user" }])).status).toBe(404);
    await result("create_payment", [{ ...base, id: "dup1" + uniq(), ref: "SAMEREF" + uniq("") }]);
  });

  it("keeps chats and projects per owner and refuses to overwrite someone else's", async () => {
    const a = (await signedUp()).json.user.id;
    const b = (await signedUp()).json.user.id;
    const pid = uniq("chat");
    await result("put_project", [pid, { id: pid, uid: a, title: "mine", created_at: 10, updated_at: 20, group_id: null }]);
    await result("put_project", [pid, { id: pid, uid: b, title: "hijack", created_at: 10, updated_at: 30 }]);
    expect((await result("get_project", [pid])).title).toBe("mine");
    await result("put_project", [pid, { id: pid, uid: a, title: "renamed", created_at: 10, updated_at: 40, group_id: "g1" }]);
    expect((await result("get_project", [pid])).title).toBe("renamed");
    expect((await result("list_projects", [a])).length).toBe(1);
    expect((await result("list_projects", [b])).length).toBe(0);
    expect((await result("list_projects_before", [100])).some((p: { id: string }) => p.id === pid)).toBe(true);
    expect((await result("list_projects_before", [5])).some((p: { id: string }) => p.id === pid)).toBe(false);
    await result("delete_project", [pid]);
    expect(await result("get_project", [pid])).toBeNull();

    const gid = uniq("grp");
    await result("put_group", [gid, { id: gid, uid: a, name: "G", created_at: 5 }]);
    await result("put_group", [gid, { id: gid, uid: b, name: "hijack", created_at: 5 }]);
    expect((await result("get_group", [gid])).name).toBe("G");
    expect((await result("list_groups", [a])).length).toBe(1);
    await result("delete_group", [gid]);
    expect(await result("get_group", [gid])).toBeNull();
  });

  it("stores run archives in R2, compressed, and reads them back exactly", async () => {
    const { json } = await signedUp();
    const jid = "j" + uniq("");
    const big = { uid: json.user.id, project_id: "p", results: Array.from({ length: 4000 }, (_, i) => ({ i, name: `model-${i % 7}`, m: [[i, i + 1], [i + 2, i + 3]] })) };
    await result("put_archive", [jid, big]);
    const obj = await E.FILES.get(`archives/${jid}.json.gz`);
    expect(obj).not.toBeNull();
    expect(obj!.size).toBeLessThan(JSON.stringify(big).length / 4); // gzip actually shrank it
    expect(await result("get_archive", [jid])).toEqual(big);
    await result("delete_archive", [jid]);
    expect(await result("get_archive", [jid])).toBeNull();
    expect((await call("put_archive", ["../../etc/passwd", {}])).status).toBe(400);
  });

  it("handles VIP, events and feedback", async () => {
    const e = `${uniq("vip")}@example.com`;
    await result("add_vip", [e.toUpperCase()]);
    await result("add_vip", [e]);
    expect((await result("get_vip", [])).filter((x: string) => x === e)).toHaveLength(1);
    await result("remove_vip", [e]);
    expect(await result("get_vip", [])).not.toContain(e);
    const ts = Date.now() / 1000;
    await result("add_event", [{ ts, uid: "u1", domain: "Finance" }]);
    expect((await result("list_events", [ts - 1])).some((x: { domain?: string }) => x.domain === "Finance")).toBe(true);
    await result("add_feedback", [{ ts, uid: "u1", rating: 5, text: "great" }]);
    expect((await result("list_feedback", [5]))[0].text).toBe("great");
  });
});
