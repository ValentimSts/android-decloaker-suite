import { describe, it, expect, vi, beforeEach } from "vitest";
import { log } from "../agent/core/logger";
import { config } from "../agent/config";

describe("logger", () => {
  let spy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    spy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  it("suppresses setup lines when quiet", () => {
    config.quietSetup = true;
    log.setup("SYS-PROP", "hooked");
    expect(spy).not.toHaveBeenCalled();
  });

  it("never suppresses detections when quiet", () => {
    config.quietSetup = true;
    log.detect("SYS-PROP", "match", [["value", "frida"]]);
    expect(spy).toHaveBeenCalled();
    const out = spy.mock.calls.map((c) => c[0]).join("\n");
    expect(out).toContain("[!]");
    expect(out).toContain("[SYS-PROP]");
    expect(out).toContain("frida");
  });

  it("emits setup lines when not quiet", () => {
    config.quietSetup = false;
    log.setup("SYS-PROP", "hooked");
    expect(spy).toHaveBeenCalled();
    expect(String(spy.mock.calls[0][0])).toContain("[+]");
  });
});
