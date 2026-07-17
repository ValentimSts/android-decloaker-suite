import { describe, it, expect, beforeEach } from "vitest";
import { hasSeen, markSeen, resetSeen } from "../agent/core/dedup";

describe("dedup", () => {
  beforeEach(() => resetSeen());

  it("tracks seen signatures", () => {
    expect(hasSeen("a")).toBe(false);
    markSeen("a");
    expect(hasSeen("a")).toBe(true);
  });

  it("resets when exceeding the cap", () => {
    for (let i = 0; i < 5001; i++) markSeen("k" + i);
    // After crossing the cap the store resets, so the earliest keys are gone.
    expect(hasSeen("k0")).toBe(false);
  });
});
