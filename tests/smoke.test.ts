import { describe, it, expect } from "vitest";
import { fakePtr } from "./setup";

describe("test harness", () => {
  it("fakePtr reads bytes", () => {
    const p = fakePtr([0x64, 0x65, 0x78, 0x0a]);
    expect(new Uint8Array(p.readByteArray(4))[0]).toBe(0x64);
  });
});
