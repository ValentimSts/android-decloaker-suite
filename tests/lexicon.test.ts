import { describe, it, expect } from "vitest";
import { TARGET_STRINGS, TARGET_REGEX, pathIsSpoofable } from "../agent/filters/lexicon";

describe("lexicon", () => {
  it("regex matches each token literally", () => {
    for (const t of TARGET_STRINGS) {
      TARGET_REGEX.lastIndex = 0;
      expect(TARGET_REGEX.test(t)).toBe(true);
    }
  });

  it("escapes regex metacharacters", () => {
    TARGET_REGEX.lastIndex = 0;
    expect(TARGET_REGEX.test("market://details?id=abc")).toBe(true);
  });

  it("pathIsSpoofable matches narrow allowlist artifacts", () => {
    expect(pathIsSpoofable("/dev/qemu_pipe")).toBe(true);
    expect(pathIsSpoofable("/data/app/normal.apk")).toBe(false);
  });

  // Retune assertions (approved): mcc/mnc dropped, timezone narrowed, organic retained.
  it("drops mcc and mnc from the lexicon", () => {
    expect(TARGET_STRINGS).not.toContain("mcc");
    expect(TARGET_STRINGS).not.toContain("mnc");
  });

  it("narrows the bare timezone token to persist.sys.timezone", () => {
    expect(TARGET_STRINGS).toContain("persist.sys.timezone");
    expect(TARGET_STRINGS).not.toContain("timezone");
  });

  it("retains organic despite being a broad token", () => {
    expect(TARGET_STRINGS).toContain("organic");
  });
});
