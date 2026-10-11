import { describe, expect, it } from "vitest";
import fixture from "./limits.fixture.json";
import { snapshot, type UsageDoc } from "../src/lib/limits";

// limits.fixture.json is produced by the Python engine (backend/app/limits.py), so these numbers cannot drift apart.
describe("usage window parity with the Python engine", () => {
  for (const [i, c] of fixture.entries()) {
    it(`case ${i + 1}`, () => {
      const u: UsageDoc = { window_start: c.input.window_start, free_used: c.input.free_used, paid_used: c.input.paid_used, verified_spend: c.input.verified_spend, reports_used: c.input.reports_used, paid_blocked: c.input.paid_blocked };
      expect(snapshot(u, c.input.now, c.input.unlimited)).toEqual(c.expected);
    });
  }
});
