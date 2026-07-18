import { describe, it, expect } from "vitest";
import { config } from "../agent/config";

describe("config defaults", () => {
  it("starts observe-only with quiet setup", () => {
    expect(config.activeBypass).toBe(false);
    expect(config.dumpPayloads).toBe(false);
    expect(config.quietSetup).toBe(true);
    expect(config.hookMemoryProtection).toBe(false);
    expect(config.dumpDir).toBe("/data/local/tmp");
  });
});
