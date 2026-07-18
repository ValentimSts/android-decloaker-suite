import { describe, it, expect } from "vitest";
import { selectEnabled } from "../agent/modules/index";
import type { DecloakerModule } from "../agent/types";

const mk = (id: string, enabledByDefault: boolean): DecloakerModule => ({
  id, tag: id.toUpperCase(), description: "", enabledByDefault, install() {},
});

describe("selectEnabled", () => {
  it("returns only modules whose flag is on", () => {
    const reg = [mk("a", true), mk("b", false)];
    const cfg = { modules: { a: true, b: false } } as any;
    expect(selectEnabled(reg, cfg).map((m) => m.id)).toEqual(["a"]);
  });
});
