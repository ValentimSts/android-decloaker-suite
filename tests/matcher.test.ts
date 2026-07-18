import { describe, it, expect, vi, beforeEach } from "vitest";
import { scan } from "../agent/filters/matcher";
import { resetSeen } from "../agent/core/dedup";
import { config } from "../agent/config";

describe("scan", () => {
  beforeEach(() => {
    resetSeen();
    config.targetModules = [];
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("returns the matched token", () => {
    expect(scan("TEST", "path=/system/bin/su here")).toBe("/system/bin/su");
  });

  it("returns false when nothing matches", () => {
    expect(scan("TEST", "totally benign string")).toBe(false);
  });

  it("returns the canonical lexicon casing, not the source casing", () => {
    expect(scan("TEST", "found /data/superuser.apk on disk")).toBe("Superuser.apk");
  });

  it("logs a detection only once per signature", () => {
    const spy = console.log as unknown as ReturnType<typeof vi.fn>;
    scan("TEST", "frida-server running");
    const first = spy.mock.calls.length;
    scan("TEST", "frida-server running");
    expect(spy.mock.calls.length).toBe(first);
  });
});
