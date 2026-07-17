import { describe, it, expect } from "vitest";
import { formatBacktrace } from "../agent/core/backtrace";
import { config } from "../agent/config";

describe("formatBacktrace", () => {
  it("returns a placeholder for empty input", () => {
    expect(formatBacktrace("")).toContain("unavailable");
  });

  it("truncates to 5 frames unless fullBacktrace", () => {
    config.fullBacktrace = false;
    const bt = ["f0", "f1", "f2", "f3", "f4", "f5", "f6"].join("\n    ");
    const out = formatBacktrace(bt);
    expect(out).toContain("TRUNCATED");
    expect(out.split("\n    ").length).toBeLessThanOrEqual(6);
  });

  it("keeps everything when fullBacktrace is on", () => {
    config.fullBacktrace = true;
    const bt = ["f0", "f1", "f2", "f3", "f4", "f5", "f6"].join("\n    ");
    expect(formatBacktrace(bt)).toBe(bt);
  });
});
