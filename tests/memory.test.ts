import { describe, it, expect } from "vitest";
import { payloadMagic, hexPreview } from "../agent/core/memory";
import { fakePtr } from "./setup";

describe("payloadMagic", () => {
  it("detects dex", () => {
    expect(payloadMagic(fakePtr([0x64, 0x65, 0x78, 0x0a]) as any)).toBe("dex");
  });
  it("detects elf", () => {
    expect(payloadMagic(fakePtr([0x7f, 0x45, 0x4c, 0x46]) as any)).toBe("elf");
  });
  it("returns null for unknown", () => {
    expect(payloadMagic(fakePtr([0, 1, 2, 3]) as any)).toBe(null);
  });
});

describe("hexPreview", () => {
  it("hex-encodes bytes", () => {
    expect(hexPreview(fakePtr([0x00, 0xff, 0x10]) as any, 3)).toBe("00ff10");
  });
});
