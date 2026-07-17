# Decloaker Suite Modularization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the 5,962-line `decloaker.js` monolith into a modular, flag-driven Frida 17 TypeScript agent compiled with `frida-compile`, preserving all current detection and active-bypass behavior.

**Architecture:** One bundled agent compiled from a module tree. A thin `core/` (logger, dedup, backtrace, memory, attach, java) and `filters/` (lexicon, matcher) layer supports ~27 self-registering hook modules. A central `config` object plus RPC exports drive granular per-module and per-behavior flags. `index.ts` walks an ordered registry and installs each enabled module inside try/catch.

**Tech Stack:** TypeScript, `frida-compile`, `@types/frida-gum`, `frida-java-bridge`, Vitest (unit tests for pure logic), pnpm, Frida 17.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the spec and the source analysis.

- **Frida version:** target Frida 17. Language bridges are not in the GumJS core: Java modules MUST `import Java from "frida-java-bridge"`. The bridge ships its own TypeScript types; no `@types` package is needed.
- **`this`-binding (G-THIS):** Interceptor `onEnter`/`onLeave` handlers and Java `.implementation` bodies MUST be classic `function` expressions, never arrow functions, so Frida rebinds `this` (the `InvocationContext` or the Java instance) per call. Where a handler stashes ad-hoc fields on `this` (e.g. `this.skip`, `this.ctx`), type `this` with an `InvocationContext`-extending interface.
- **Lazy backtrace (G-TRACE):** the matcher's `scan(source, value, traceCb?)` calls `traceCb` as a bare function. In handlers, copy `this.context` into a local `ctx` in `onEnter`/`onLeave`, then pass `() => getNativeBacktrace(ctx)` (or `formatBacktrace(getNativeBacktrace(ctx))`). NEVER reference `this` inside that thunk.
- **Pointer/endianness fidelity (G-PTR):** preserve `Process.pointerSize === 8` branches (struct offsets, read widths) and byte-order assumptions (`readU16`/`readU32`/`readU64`, big-endian ports) exactly. Use instance `NativePointer` methods (`ptr.readPointer()`, `ptr.readByteArray()`); static `Memory.readPointer` was removed in Frida 17.
- **Behavior preservation (G-BEHAVIOR):** same detection tokens (except the signed-off retune in Task 12), same active-bypass logic, same log content re-expressed through the logger with the same tag and severity. Module install order in the registry reproduces the original `setImmediate` dispatch order.
- **ASCII only (G-ASCII):** all source, comments, identifiers, and string literals are plain ASCII. No em dashes, curly quotes, arrows, or emoji. Use `->` in log text.
- **Modern JS (G-JS):** `var` becomes `const`/`let`. Preserve per-iteration `let`/`const` bindings in loops whose bodies create Interceptor closures (or every closure captures the last value).
- **Module contract (G-CONTRACT):** every hook module default-exports a `DecloakerModule` and is registered in `agent/modules/index.ts`. The four repaired-but-risky modules ship with `enabledByDefault: false`.
- **Package manager:** pnpm. Use `pnpm install`, `pnpm run build`, `pnpm run typecheck`, `pnpm test`.
- **No AI attribution** in commits (per repo policy). Conventional Commits, ASCII, subject under 72 chars.

## Source-of-truth mapping

The original `decloaker.js` stays in the repo (untracked) as the porting reference during the whole refactor. Each module task cites exact line ranges to port from it.

---

## Phase A: Project scaffolding

### Task 1: Initialize the frida-compile TypeScript project

**Files:**
- Create: `package.json`, `tsconfig.json`, `.gitignore`, `agent/index.ts`

**Interfaces:**
- Produces: a buildable agent skeleton; `pnpm run build` emits `_agent.js`.

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "android-decloaker-suite",
  "version": "0.1.0",
  "description": "Frida script suite for Android app analysis",
  "license": "MIT",
  "private": true,
  "scripts": {
    "build": "frida-compile agent/index.ts -o _agent.js -S -c",
    "build:dev": "frida-compile agent/index.ts -o _agent.js",
    "watch": "frida-compile agent/index.ts -o _agent.js -w",
    "typecheck": "tsc --noEmit",
    "test": "vitest run"
  },
  "devDependencies": {
    "@types/frida-gum": "^18.0.0",
    "frida-compile": "^17.0.0",
    "typescript": "^5.4.0",
    "vitest": "^1.6.0"
  },
  "dependencies": {
    "frida-java-bridge": "^7.0.0"
  }
}
```

- [ ] **Step 2: Create `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "es2020",
    "module": "es2020",
    "moduleResolution": "bundler",
    "lib": ["es2020"],
    "types": ["frida-gum"],
    "strict": true,
    "noUnusedLocals": true,
    "noImplicitReturns": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": "."
  },
  "include": ["agent/**/*.ts"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

- [ ] **Step 3: Create `.gitignore`**

```
node_modules/
dist/
_agent.js
_agent.js.map
*.log
```

- [ ] **Step 4: Create a minimal `agent/index.ts`**

```ts
setImmediate(() => {
  console.log("[*] android-decloaker-suite agent loaded (skeleton)");
});
```

- [ ] **Step 5: Install and build**

Run: `pnpm install && pnpm run build`
Expected: `_agent.js` is produced with no errors.

- [ ] **Step 6: Commit**

```bash
git add package.json tsconfig.json .gitignore agent/index.ts
git commit -m "build: scaffold frida-compile typescript agent project"
```

### Task 2: Add Vitest and a Frida-globals test shim

**Files:**
- Create: `vitest.config.ts`, `tests/setup.ts`, `tests/smoke.test.ts`

**Interfaces:**
- Produces: `pnpm test` runs; `tests/setup.ts` exposes helpers to fake Frida globals (`Process`, `Thread`, `DebugSymbol`, `NativePointer`-like) for pure-logic tests. Later test tasks import from here.

- [ ] **Step 1: Create `vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: ["tests/setup.ts"],
    include: ["tests/**/*.test.ts"],
  },
});
```

- [ ] **Step 2: Create `tests/setup.ts`** (a fake NativePointer for pure buffer helpers)

```ts
// Minimal stand-ins so pure-logic modules that touch a few Frida globals or
// NativePointer methods can be unit-tested under Node. Hook modules are NOT
// unit-tested here; their gate is typecheck + build.
export function fakePtr(bytes: number[]) {
  return {
    isNull: () => false,
    readByteArray: (n: number) => new Uint8Array(bytes.slice(0, n)).buffer,
    toString: () => "0xfake",
  };
}
```

- [ ] **Step 3: Create `tests/smoke.test.ts`**

```ts
import { describe, it, expect } from "vitest";
import { fakePtr } from "./setup";

describe("test harness", () => {
  it("fakePtr reads bytes", () => {
    const p = fakePtr([0x64, 0x65, 0x78, 0x0a]);
    expect(new Uint8Array(p.readByteArray(4))[0]).toBe(0x64);
  });
});
```

- [ ] **Step 4: Run tests and typecheck**

Run: `pnpm test && pnpm run typecheck`
Expected: 1 test passes; typecheck clean.

- [ ] **Step 5: Commit**

```bash
git add vitest.config.ts tests/
git commit -m "test: add vitest harness and frida-globals shim"
```

---

## Phase B: Core primitives and filters (TDD)

### Task 3: Shared types

**Files:**
- Create: `agent/types.ts`

**Interfaces:**
- Produces: `DecloakerModule`, `LogLevel`, `TraceThunk`, `Config`, `IC` (InvocationContext augmentation). Every later task imports from here.

- [ ] **Step 1: Write `agent/types.ts`**

```ts
import type { InvocationContext } from "frida-gum";

export type LogLevel = "detect" | "bypass" | "dump" | "setup" | "warn" | "info";

export type TraceThunk = () => string;

/** InvocationContext plus the ad-hoc fields handlers stash on `this`. */
export type IC = InvocationContext & Record<string, any>;

export interface DecloakerModule {
  id: string;
  tag: string;
  description: string;
  enabledByDefault: boolean;
  requires?: "java" | "il2cpp";
  install(): void;
}

export interface Config {
  activeBypass: boolean;
  dumpPayloads: boolean;
  dumpDir: string;
  fullBacktrace: boolean;
  truncateHex: boolean;
  quietSetup: boolean;
  hookMemoryProtection: boolean;
  targetModules: string[];
  modules: Record<string, boolean>;
}
```

- [ ] **Step 2: Typecheck**

Run: `pnpm run typecheck`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add agent/types.ts
git commit -m "feat: add shared decloaker types"
```

### Task 4: Config object

**Files:**
- Create: `agent/config.ts`
- Test: `tests/config.test.ts`

**Interfaces:**
- Consumes: `Config` from `agent/types.ts`.
- Produces: `config` (mutable singleton). `modules` map is populated from the registry in Task 13; it starts empty here.

- [ ] **Step 1: Write the failing test `tests/config.test.ts`**

```ts
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/config.test.ts`
Expected: FAIL (cannot find `../agent/config`).

- [ ] **Step 3: Write `agent/config.ts`**

```ts
import type { Config } from "./types";

// Compile-time defaults. Mutated at runtime by rpc.ts.
// Observe-first: activeBypass defaults OFF (confirmed with the user). The
// original V28 file shipped ACTIVE_BYPASS=true, but its own comment documented
// OFF; enable at runtime via rpc.setbypass(true) to deliberately defeat cloaking.
export const config: Config = {
  activeBypass: false,
  dumpPayloads: false,
  dumpDir: "/data/local/tmp",
  fullBacktrace: false,
  truncateHex: false,
  quietSetup: true,
  hookMemoryProtection: false,
  targetModules: [],
  modules: {},
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test tests/config.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/config.ts tests/config.test.ts
git commit -m "feat: add mutable config with compile-time defaults"
```

> NOTE: shipped defaults confirmed with the user - `activeBypass: false` (observe-first) and `targetModules: []` (global). The original hardcoded `ACTIVE_BYPASS=true` and a sample-specific `TARGET_MODULES` are intentionally not carried over.

### Task 5: Dedup cache

**Files:**
- Create: `agent/core/dedup.ts`
- Test: `tests/dedup.test.ts`

**Interfaces:**
- Produces: `hasSeen(sig: string): boolean`, `markSeen(sig: string): void`, `resetSeen(): void`. Backed by a bounded map (cap 5000) that resets when full. Replaces the global `ALERT_HISTORY`/`markSeen`.

- [ ] **Step 1: Write the failing test `tests/dedup.test.ts`**

```ts
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/dedup.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write `agent/core/dedup.ts`**

```ts
const CAP = 5000;
let store: Record<string, true> = {};
let size = 0;

export function hasSeen(sig: string): boolean {
  return store[sig] === true;
}

export function markSeen(sig: string): void {
  if (size >= CAP) {
    store = {};
    size = 0;
  }
  store[sig] = true;
  size++;
}

export function resetSeen(): void {
  store = {};
  size = 0;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test tests/dedup.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/core/dedup.ts tests/dedup.test.ts
git commit -m "feat: add bounded dedup cache"
```

### Task 6: Logger

**Files:**
- Create: `agent/core/logger.ts`
- Test: `tests/logger.test.ts`

**Interfaces:**
- Consumes: `config` (for `quietSetup`), `LogLevel`, `hasSeen`/`markSeen`.
- Produces:
  - `C` (ANSI palette: `RESET`, `RED`, `GREEN`, `YELLOW`, `BLUE`, `PURPLE`, `CYAN`).
  - `log.detect(tag, headline, fields?)`, `log.bypass(...)`, `log.dump(...)`, `log.setup(...)`, `log.warn(...)`, `log.info(...)` where `fields?: Array<[label: string, value: string]>` and an optional `trace?: string`.
  - `log.once(sig: string, fn: () => void): void` (dedup wrapper).
  - `logLine(level, tag, message)` low-level for banner lines.
  - `setup` lines are suppressed when `config.quietSetup` is true; `detect`/`bypass`/`dump` are never suppressed.

- [ ] **Step 1: Write the failing test `tests/logger.test.ts`**

```ts
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/logger.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write `agent/core/logger.ts`**

```ts
import { config } from "../config";
import { hasSeen, markSeen } from "./dedup";
import type { LogLevel } from "../types";

export const C = {
  RESET: "\x1b[39;49;00m",
  RED: "\x1b[31;01m",
  GREEN: "\x1b[32;01m",
  YELLOW: "\x1b[33;01m",
  BLUE: "\x1b[34;01m",
  PURPLE: "\x1b[35;01m",
  CYAN: "\x1b[36;01m",
};

const MARK: Record<LogLevel, string> = {
  detect: "[!]",
  bypass: "[BYPASS]",
  dump: "[DUMP]",
  setup: "[+]",
  warn: "[-]",
  info: "[*]",
};

const COLOR: Record<LogLevel, string> = {
  detect: C.RED,
  bypass: C.RED,
  dump: C.PURPLE,
  setup: C.GREEN,
  warn: C.YELLOW,
  info: C.CYAN,
};

type Field = [label: string, value: string];

function emit(level: LogLevel, tag: string, headline: string, fields?: Field[], trace?: string) {
  if (level === "setup" && config.quietSetup) return;
  const head = `\n${COLOR[level]}${MARK[level]} [${tag}] ${headline}${C.RESET}`;
  console.log(head);
  if (fields) {
    for (const [label, value] of fields) {
      console.log(`${C.YELLOW}    -> ${label}: ${value}${C.RESET}`);
    }
  }
  if (trace) {
    console.log(`${C.BLUE}    -> Source Backtrace:\n    ${trace}${C.RESET}`);
  }
}

export const log = {
  detect: (tag: string, headline: string, fields?: Field[], trace?: string) =>
    emit("detect", tag, headline, fields, trace),
  bypass: (tag: string, headline: string, fields?: Field[]) =>
    emit("bypass", tag, headline, fields),
  dump: (tag: string, headline: string, fields?: Field[]) =>
    emit("dump", tag, headline, fields),
  setup: (tag: string, headline: string) => emit("setup", tag, headline),
  warn: (tag: string, headline: string) => emit("warn", tag, headline),
  info: (tag: string, headline: string) => emit("info", tag, headline),
  once(sig: string, fn: () => void) {
    if (hasSeen(sig)) return;
    markSeen(sig);
    fn();
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test tests/logger.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add agent/core/logger.ts tests/logger.test.ts
git commit -m "feat: add leveled tagged logger with quiet filter"
```

### Task 7: Backtrace helpers

**Files:**
- Create: `agent/core/backtrace.ts`
- Test: `tests/backtrace.test.ts`

**Interfaces:**
- Consumes: `config` (`fullBacktrace`, `targetModules`).
- Produces: `getNativeBacktrace(context): string`, `formatBacktrace(bt: string): string`, `isTargetCaller(returnAddress): boolean`. Only `formatBacktrace` is unit-tested (pure string logic); the other two wrap `Thread.backtrace` / `Process.findModuleByAddress`.

- [ ] **Step 1: Write the failing test `tests/backtrace.test.ts`**

```ts
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/backtrace.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write `agent/core/backtrace.ts`** (port lines 205-229 of `decloaker.js`, config-backed)

```ts
import { config } from "../config";
import type { CpuContext } from "frida-gum";

export function getNativeBacktrace(context: CpuContext): string {
  try {
    return Thread.backtrace(context, Backtracer.FUZZY)
      .map(DebugSymbol.fromAddress)
      .join("\n    ");
  } catch (e) {
    return "";
  }
}

export function formatBacktrace(bt: string): string {
  if (!bt) return "[Native Backtrace unavailable]";
  if (config.fullBacktrace) return bt;
  const lines = bt.split("\n    ");
  if (lines.length > 5) {
    return lines.slice(0, 5).join("\n    ") + "\n    ... [TRUNCATED - set fullBacktrace to expand]";
  }
  return bt;
}

export function isTargetCaller(returnAddress: NativePointer): boolean {
  if (config.targetModules.length === 0) return true;
  const mod = Process.findModuleByAddress(returnAddress);
  if (!mod) return false;
  return config.targetModules.indexOf(mod.name) !== -1;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test tests/backtrace.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/core/backtrace.ts tests/backtrace.test.ts
git commit -m "feat: add config-backed backtrace helpers"
```

### Task 8: Memory and payload helpers

**Files:**
- Create: `agent/core/memory.ts`
- Test: `tests/memory.test.ts`

**Interfaces:**
- Consumes: `config` (`truncateHex`, `dumpPayloads`, `dumpDir`), `log`, `hasSeen`/`markSeen`.
- Produces: `getExportSafe(mod, fn): NativePointer | null`, `readStrSafe(ptr, limit?): string`, `hexPreview(ptr, maxLen?): string`, `payloadMagic(ptr): "dex"|"cdex"|"elf"|"zip"|null`, `dumpBuffer(tag, ptr, len): void`. `payloadMagic` and `hexPreview` are unit-tested with `fakePtr`.

- [ ] **Step 1: Write the failing test `tests/memory.test.ts`**

```ts
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/memory.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write `agent/core/memory.ts`** (port lines 188-203, 292-356 of `decloaker.js`; `console.log` calls become `log.*`)

Port `getExportSafe`, `readStrSafe`, `hexPreview`, `payloadMagic`, `dumpBuffer` verbatim in behavior, converting `var`->`const`/`let`, reading `config.truncateHex`/`config.dumpPayloads`/`config.dumpDir`, and routing `dumpBuffer`'s output through `log.dump` and `log.warn`. Keep the 16 MB dump safety cap and the dedup signature.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test tests/memory.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/core/memory.ts tests/memory.test.ts
git commit -m "feat: add memory and payload helpers"
```

### Task 9: Shared native-attach helper

**Files:**
- Create: `agent/core/attach.ts`

**Interfaces:**
- Consumes: `getExportSafe`, `isTargetCaller`, `readStrSafe`, `getNativeBacktrace`, matcher `scan` (Task 12), `C`.
- Produces: `safeAttachDetect(moduleName, funcName, argIndex)` and the shared `_detectAttached` dedupe cache. Ported from lines 1236-1259. Used by `fs-recon` (active) and `library-loading` (disabled).

- [ ] **Step 1: Write `agent/core/attach.ts`** porting `safeAttachDetect` (lines 1236-1259). Apply G-THIS and G-TRACE. `_detectAttached` is a module-private `Record<string, true>` keyed by resolved pointer string.

- [ ] **Step 2: Typecheck**

Run: `pnpm run typecheck`
Expected: clean (may need matcher stub if Task 12 not yet done; order this task after Task 12 or import lazily).

- [ ] **Step 3: Commit**

```bash
git add agent/core/attach.ts
git commit -m "feat: add shared safeAttachDetect native helper"
```

### Task 10: Java bridge helpers

**Files:**
- Create: `agent/core/java.ts`

**Interfaces:**
- Produces: re-export `Java` from `frida-java-bridge`; `withJava(fn: () => void): void` (guards `Java.available` + `Java.perform`); `jbytesToHex`, `jbytesToPrintable`, `jbytesToNative`, `jbytesSlice` (ported from lines 2649-2740). `requires: "java"` modules import from here.

- [ ] **Step 1: Write `agent/core/java.ts`**

```ts
import Java from "frida-java-bridge";
export { Java };

export function withJava(fn: () => void): void {
  if (!Java.available) return;
  Java.perform(fn);
}
```

Then port `jbytesToHex`/`jbytesToPrintable`/`jbytesToNative`/`jbytesSlice` from lines 2649-2740 (apply G-JS; `jbytesToNative` builds a plain unsigned-byte array for `writeByteArray`).

- [ ] **Step 2: Typecheck**

Run: `pnpm run typecheck`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add agent/core/java.ts
git commit -m "feat: add java bridge helpers and jbytes converters"
```

### Task 11: Lexicon

**Files:**
- Create: `agent/filters/lexicon.ts`
- Test: `tests/lexicon.test.ts`

**Interfaces:**
- Produces: `TARGET_STRINGS` (categorized), `BENIGN_FILTERS`, `SPOOF_STRINGS`, derived `TARGET_LOWER`, `TARGET_REGEX` (a single capture-group regex), `pathIsSpoofable(value): boolean`. Ported from lines 81-182.

- [ ] **Step 1: Write the failing test `tests/lexicon.test.ts`**

```ts
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
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/lexicon.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write `agent/filters/lexicon.ts`**

Port `BENIGN_FILTERS` (81-92), `TARGET_STRINGS` (97-145 grouped by the existing category comments), `SPOOF_STRINGS` (159-171), `pathIsSpoofable` (175-182). Build the regex with a single capture group so `scan` gets the token and index in one pass:

```ts
export const TARGET_REGEX = new RegExp(
  "(" + TARGET_STRINGS.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")",
  "i"
);
export const TARGET_LOWER = TARGET_STRINGS.map((s) => s.toLowerCase());
```

- [ ] **Step 4: Apply the approved lexicon retune**

The retune is decided (user-approved). Apply exactly:
- DROP: `mcc`, `mnc` (match as substrings of many benign identifiers).
- NARROW: `timezone` -> `persist.sys.timezone`.
- KEEP (deliberately retained): `organic` (heavily used in campaign/conversion-data cloaking), `.bundle`, `adb_enabled`, `type_vpn`, and every other current token.

Add assertions to `tests/lexicon.test.ts`: `mcc`/`mnc` are absent from `TARGET_STRINGS`, `persist.sys.timezone` is present, bare `timezone` is not, and `organic` is retained. Record the retune in the commit body.

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm test tests/lexicon.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add agent/filters/lexicon.ts tests/lexicon.test.ts
git commit -m "feat: add categorized detection lexicon with capture-group regex"
```

### Task 12: Matcher (single-pass scan)

**Files:**
- Create: `agent/filters/matcher.ts`
- Test: `tests/matcher.test.ts`

**Interfaces:**
- Consumes: `TARGET_REGEX`, `TARGET_STRINGS`, `BENIGN_FILTERS`, `config.targetModules`, `log`, `hasSeen`/`markSeen`, `formatBacktrace`.
- Produces: `scan(source: string, value: string, traceCb?: TraceThunk): string | false`. Returns the matched token (or `false`). Emits one deduped `detect` log with a 200-char highlighted context window. This replaces `checkAndLog` (lines 231-285) and collapses the two-pass regex+indexOf into one `TARGET_REGEX.exec`.

- [ ] **Step 1: Write the failing test `tests/matcher.test.ts`**

```ts
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

  it("logs a detection only once per signature", () => {
    const spy = console.log as unknown as ReturnType<typeof vi.fn>;
    scan("TEST", "frida-server running");
    const first = spy.mock.calls.length;
    scan("TEST", "frida-server running");
    expect(spy.mock.calls.length).toBe(first);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/matcher.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write `agent/filters/matcher.ts`**

```ts
import { TARGET_REGEX, BENIGN_FILTERS } from "./lexicon";
import { config } from "../config";
import { log, C } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { formatBacktrace } from "../core/backtrace";
import type { TraceThunk } from "../types";

export function scan(source: string, value: string, traceCb?: TraceThunk): string | false {
  if (!value) return false;
  TARGET_REGEX.lastIndex = 0;
  const m = TARGET_REGEX.exec(value);
  if (!m) return false;

  const backtrace = traceCb ? traceCb() : "";

  if (config.targetModules.length === 0 && backtrace) {
    const btLower = backtrace.toLowerCase();
    for (const b of BENIGN_FILTERS) {
      if (btLower.indexOf(b.toLowerCase()) !== -1) return false;
    }
  }

  const token = m[1];
  const idx = m.index;
  const start = Math.max(0, idx - 100);
  const end = Math.min(value.length, idx + token.length + 100);
  const before = value.substring(start, idx).replace(/\n/g, " ");
  const after = value.substring(idx + token.length, end).replace(/\n/g, " ");
  const highlighted =
    (start > 0 ? "... " : "") +
    before + C.GREEN + token + C.YELLOW + after +
    (end < value.length ? " ..." : "");

  const formattedBt = formatBacktrace(backtrace);
  const cleanSig = value.substring(0, 150).replace(/\n/g, " ");
  const signature = token + "|" + cleanSig + "|" + formattedBt;

  if (!hasSeen(signature)) {
    markSeen(signature);
    log.detect(source, "Detected target string match: " + token,
      [["Value", highlighted]], backtrace ? formattedBt : undefined);
  }
  return token;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm test tests/matcher.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent/filters/matcher.ts tests/matcher.test.ts
git commit -m "feat: add single-pass detection matcher"
```

---

## Phase C: Module infrastructure

### Task 13: Registry, dispatcher, and RPC

**Files:**
- Create: `agent/modules/index.ts`, `agent/rpc.ts`
- Modify: `agent/index.ts`, `agent/config.ts`
- Test: `tests/dispatch.test.ts`

**Interfaces:**
- Consumes: `DecloakerModule`, `config`, `log`.
- Produces:
  - `registry: DecloakerModule[]` (empty array to start; module tasks push into it).
  - `seedModuleFlags(): void` - fills `config.modules[id]` from each module's `enabledByDefault`.
  - `selectEnabled(reg, cfg): DecloakerModule[]` - pure function returning modules whose flag is on (used by dispatch and unit-tested).
  - `installAll(): void` - seeds flags, iterates registry, skips disabled and unmet `requires`, installs each enabled module in try/catch, logging `setup`/`warn`.
  - `rpc.exports`: `addtarget`, `cleartargets`, `setfulltrace`, `setbypass`, `setdump`, `setquiet`, `settruncatehex`, `enable(id)`, `disable(id)`, `enableonly(...ids)`, `list()`.

- [ ] **Step 1: Write the failing test `tests/dispatch.test.ts`**

```ts
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm test tests/dispatch.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write `agent/modules/index.ts`**

```ts
import type { Config, DecloakerModule } from "../types";
import { config } from "../config";
import { log } from "../core/logger";
import { Java } from "../core/java";

export const registry: DecloakerModule[] = [];

export function seedModuleFlags(): void {
  for (const m of registry) {
    if (config.modules[m.id] === undefined) config.modules[m.id] = m.enabledByDefault;
  }
}

export function selectEnabled(reg: DecloakerModule[], cfg: Config): DecloakerModule[] {
  return reg.filter((m) => cfg.modules[m.id]);
}

function envReady(m: DecloakerModule): boolean {
  if (m.requires === "java") return Java.available;
  if (m.requires === "il2cpp") return Process.findModuleByName("libil2cpp.so") !== null;
  return true;
}

export function installAll(): void {
  seedModuleFlags();
  for (const m of selectEnabled(registry, config)) {
    if (!envReady(m)) {
      log.warn(m.tag, "skipped: environment for '" + m.requires + "' not available");
      continue;
    }
    try {
      m.install();
      log.setup(m.tag, "installed");
    } catch (e: any) {
      log.warn(m.tag, "install failed: " + (e && e.message ? e.message : e));
    }
  }
}
```

- [ ] **Step 4: Write `agent/rpc.ts`** (delegates to `config` + `registry`) and wire `agent/index.ts` to print the banner and call `installAll()` inside `setImmediate`. The `il2cpp` late-load wait lives in the unity module (Task 36); the dispatcher only checks availability once. Note in `index.ts` that `il2cpp`-required modules that are enabled but not yet loaded should be retried by the unity module's own installer.

- [ ] **Step 5: Run test + typecheck + build**

Run: `pnpm test tests/dispatch.test.ts && pnpm run typecheck && pnpm run build`
Expected: PASS, clean, `_agent.js` emitted.

- [ ] **Step 6: Commit**

```bash
git add agent/modules/index.ts agent/rpc.ts agent/index.ts agent/config.ts tests/dispatch.test.ts
git commit -m "feat: add module registry, dispatcher, and rpc toggles"
```

---

## Phase D: Port the hook modules

This phase is a parallel fan-out (one module per task). Every task follows the same **Porting Protocol**; each module's unique data is in the table below. Run the fan-out with a Workflow (worktree isolation per agent), then integrate.

### Porting Protocol (applies to every Task in Phase D)

For module `<id>` porting source lines `L1-L2`:

1. Read `decloaker.js` lines `L1-L2` (plus any listed local helpers/consts elsewhere).
2. Create `agent/modules/<id>.ts`. Move the `hook*` body and its listed `localHelpers` into the file. Apply G-JS, G-THIS, G-TRACE, G-PTR, G-ASCII.
3. Replace calls: `checkAndLog(...)` -> `scan(...)` (import from `../filters/matcher`); `console.log(C.X + "[!] [TAG] ...")` -> the matching `log.<level>(TAG, ...)` (import from `../core/logger`); shared helpers -> imports from `../core/*`; config flags (`ACTIVE_BYPASS` etc.) -> `config.*` read live.
4. Java modules: `import { Java, withJava } from "../core/java"` and wrap the body in `withJava(() => { ... })`; keep `.implementation` bodies as `function` expressions.
5. Default-export a `DecloakerModule` (`id`, `tag`, `description`, `enabledByDefault`, `requires?`) whose `install()` performs the hooking.
6. Register it: add `import <id> from "./<id>"` and push into `registry` in `agent/modules/index.ts`, keeping registry order = original dispatch order.
7. Verify: `pnpm run typecheck && pnpm run build` both clean. Commit `refactor: port <id> hook module to typescript`.

Handlers that stash fields on `this` type it as `IC` (from `../types`). Do not add unit tests for hook modules; the gate is typecheck + build.

### Module table

`java` = needs `frida-java-bridge`. `dflt` = `enabledByDefault`. Tags and per-module gotchas are copied from the source analysis; obey them.

| Task | id | src lines | java | dflt | tag(s) | key gotchas (from analysis) |
|------|-----|-----------|------|------|--------|------------------------------|
| 14 | system-properties | 400-459 | no | true | SYS-PROP, BYPASS | onEnter/onLeave share `this.propName`/`this.valBuf`; in-place `writeUtf8String` spoof gated on `config.activeBypass`; dedup per prop name |
| 15 | native-file-io | 460-476 + 856-949 + inline 5917-5931 | no | true | FILE-IO, BYPASS | merge openat detector + `safeAttachIO` family (`libcClose`/`setErrnoENOENT`/`_closeFn`/`_errnoLoc` tri-state caches) + the 12 inline attaches; `retval.replace` is InvocationReturnValue, not Interceptor.replace; `pathIsSpoofable` gates bypass |
| 16 | deep-execution | 783-855 | no | true | (execve/readlink) | `attachReadlink` local helper; capture `ctx` for trace; ptrace onLeave reads `this.ctx` |
| 17 | raw-syscalls | 1272-1333 | no | true | BYPASS (syscall ptrace) | per-call `byNum`/`PATH_AT`/`TABLES` lookups; `this.isTraceme`; bypass gated on `config.activeBypass` |
| 18 | java-dcl | 592-651 | yes | true | DCL | `logDCL` nested in perform; hooks DexClassLoader/PathClassLoader/InMemoryDexClassLoader `$init`; keep `this.$init` |
| 19 | java-evasion | 1334-1473 | yes | true | TELEPHONY, BATTERY | overload `.implementation` calling `this.<method>`; `seen` snapshot before `markSeen`; bypass gated |
| 20 | network-traffic | 652-782 | no | true | NETWORK, RAW-NET | `readPrintableString`/`detectJSON`/`processNetworkBuffer`/`NET_SCAN_CAP` locals; per-iteration `let cfg`; `config.fullBacktrace` |
| 21 | libart | 1092-1148 | no | true | JNI | FindClass hook captures `ctx`; methodCount loop uses `j*pointerSize*3` (G-PTR) |
| 22 | jni-env | 1149-1235 | yes | true | (JNIEnv table) | `hookJniMethod` -> module-private helper; `Java.vm.getEnv().handle`; table indices 33/113/167/169; instance `readPointer()` |
| 23 | jni-extended | 1474-1779 | yes | true | JNI * | move `jniRememberMethod`/`jniLookupMethod`/`JNI_METHOD_MAP*`/`JNI_REGION_READ_CAP`; nested `slot`/`attachSlot`/`attachMethodIdMapper`/`attachCallHook`/`attachFieldId` close over `vtable`/`pSize` |
| 24 | art-dex-loaders | 1780-2065 | no | true | ART-DEX, JNI_OnLoad | `looksLikeDexLoader`/`attachDexLoader`/`attachJniOnLoad` nested sharing `hookedNames`/`seenAddr`; dlopen onLeave re-enumerates modules by basename (late-load) |
| 25 | file-content | 2066-2462 | no | true | FILE-CONTENT, ANTI-DEBUG, ANTI-FRIDA | move `FC_*` state + `fc*` helpers; forEach per-iteration bindings; `this.fc*` fields (type IC); `config.dumpPayloads` |
| 26 | fs-recon | 2463-2639 | no | true | (dir/mount/stat) | `_readMntent`/`_attachTwoPathDetect`/`_DIRENT_DNAME_OFF` locals; uses shared `safeAttachDetect` from core/attach; `Process.pointerSize` offset for mnt_dir |
| 27 | crypto-java | 2640-3233 | yes | true | CRYPTO, CRYPTO KEY, CRYPTO IV | `jbytes*` now imported from core/java; `arguments`/`this` in Java impls; `gzipReadOv.call(this,...)` anti-recursion; `config.truncateHex`/`config.dumpPayloads` |
| 28 | crypto-native | 3234-3547 | no | true | CRYPTO | `cryptoReadForScan`/`cryptoInspectOutput`/`cryptoPreviewKeyMaterial`/`CRYPTO_PREVIEW_CAP` locals; LP64/ILP32 z_stream offsets + read width (G-PTR); `config.dumpPayloads` |
| 29 | memory-unpacking | 3548-3783 | no | true | mprotect, mmap, memfd_create, munmap, remap_file_pages | `protStr`/`maybeDumpExecRegion`/`PROT_*`/`MAP_ANONYMOUS` locals; mprotect/mmap/munmap/remap attaches gated on `config.hookMemoryProtection` (memfd_create always on); memfd onLeave captures `ctx` |
| 30 | reflection | 3784-3989 | yes | true | REFLECTION | pure Java bridge; `reflectBacktrace`/`logReflect`/`fieldName` nested in perform; impl `this` is the Java reflect wrapper |
| 31 | anti-debug-native | 3990-4266 | no | true | ANTI-DEBUG, BYPASS, TIMING | `_antiDbgSeen`/`ANTIDBG_SIGNALS`/`PR_*`/`TIMING_*`/`_timingCounts` locals; prctl/getppid stash `this.ctx`; bypass gated |
| 32 | property-modern | 4267-4397 | no | true | (prop read) | **NativeCallback trampolines**: `PROP_CB_TRAMPOLINES` registry MUST persist for process lifetime (GC hazard); `makePropReadTrampoline` reassigns `args[1]`; trampoline passes `null` trace to `scan`. dflt: keep `true` (it was active), see note below table |
| 33 | net-c2-native | 4398-4564 | no | true | C2 CONNECT, DNS | `parseSockaddrC2`/`compactIPv6` locals; sockaddr endianness load-bearing (G-PTR); per-iteration `let cfg`/`dnsPtr` |
| 34 | net-c2-java | 4565-4984 | yes | true | NET-C2, TLS-PIN, WS-INBOUND, BYPASS | `_PermissiveTM` tri-state cache (registerClass once); `getPermissiveTrustManager`/`javaBacktrace`/`chainToList`/`firstStringArg` locals; `ov.apply(this, arguments)` generic overload; `& 0xff` byte normalize; bypass gated |
| 35 | behavior-ipc | 4985-5442 | yes | true | SMS, A11Y, CONTENT, EXEC, PKG, PROC, IPC, CLIP | `preview`/`report`/`flagSensitiveUri`/`argvToStr`/`intentStr`/`clipStr` nested in perform; impl `this` is Java instance; bypass gated |
| 36 | unity-il2cpp | 5676-5885 | no | true | UNITY CRYPTO | `requires: "il2cpp"`; move `readIl2CppByteArray`/`getIl2CppApi`/`hookIl2cppMethod`/`hookIl2cppByOffset` together; **late-load wait**: install() sets a `setInterval` polling for `libil2cpp.so` then runs the hooks (encapsulates the original initializer interval); pSize offset branching (G-PTR); `STRIPPED_MODE`/`OFFSETS` kept as module consts |

Disabled modules (ship with `enabledByDefault: false`; repair, then leave off):

| Task | id | src lines | java | tag(s) | repair notes |
|------|-----|-----------|------|--------|--------------|
| 37 | library-loading | 1260-1271 | no | (dlopen) | thin dispatcher over `safeAttachDetect`; mechanical. Document why it destabilizes (dlopen/dlsym/getenv) in-module |
| 38 | java-native-loaders | 510-591 + scanModuleMemory 477-509 | yes | NATIVE LOAD | **repair the `isSystemLib` bug** (line 547): it is never defined. Replace the bare reference with a real system-lib check on `libname` (e.g. path under `/system/`, `/apex/`, or a known-framework basename). Move `scanModuleMemory` + `logNativeLoad` in. Keep OFF |
| 39 | strings-native | 950-1091 | no | CModule | **CModule + NativeCallback**: keep the C source template and `onMatch` NativeCallback wired together; `TARGET_STRINGS` interpolated at assembly time must be in scope; the strstr guard attach is active despite the misleading comment. Keep OFF |
| 40 | java-state-debug | 5443-5675 (incl. hookSqliteNative) | yes | ANTI-DEBUG, PREFS, SQLITE | move `hookSqliteNative` + `SQLITE_MAX_TEXT` + `prefsLog` in; SQLite onEnter captures `ctx`; Java impls dispatch via `this.<method>`. Keep OFF |

> **Note on Task 32 (property-modern) default:** it was active in the original dispatch, so `enabledByDefault: true`. It uses NativeCallback trampolines - lower-risk than the four disabled hooks but flag it in review.
> **Note on the four disabled modules:** repairs are attempted so they compile and are ready to test, but they stay `enabledByDefault: false`. The user enables each via `rpc.enable("<id>")` for manual testing.

### Registry order (Task 13 + Phase D integration)

Final `registry` order (reproduces the original `setImmediate` dispatch; disabled entries still listed, just flagged off):

```
unity-il2cpp (late-wait), native-file-io, deep-execution, raw-syscalls,
library-loading*, java-native-loaders*, system-properties, java-dcl,
java-evasion, network-traffic, strings-native*, libart, jni-env, jni-extended,
art-dex-loaders, file-content, fs-recon, crypto-java, crypto-native,
memory-unpacking, reflection, anti-debug-native, property-modern,
net-c2-native, net-c2-java, behavior-ipc, java-state-debug*
```
(`*` = disabled by default.)

---

## Phase E: Integration, parity, and documentation

### Task 41: Full-agent build and parity check

**Files:**
- Modify: `agent/index.ts`, `agent/modules/index.ts`

- [ ] **Step 1:** Confirm all 27 modules are imported and pushed into `registry` in the order above.
- [ ] **Step 2:** Run `pnpm run typecheck && pnpm run build`. Expected: clean, `_agent.js` emitted.
- [ ] **Step 3:** Parity checklist - verify every hook the original `setImmediate` installed (lines 5891-5962) has an enabled module, and every original `// BREAKS` hook maps to a disabled module. Write the checklist result into the commit body.
- [ ] **Step 4: Commit**

```bash
git add agent/
git commit -m "refactor: wire full module registry in dispatch order"
```

### Task 42: ARCHITECTURE.md

**Files:**
- Create: `ARCHITECTURE.md`

- [ ] **Step 1:** Write `ARCHITECTURE.md`: directory layout; the `DecloakerModule` contract; the config/flag model and RPC surface; the logging grammar and severity table; the filter engine (lexicon + single-pass matcher); a per-module section (id, tag, what it hooks, `requires`, default state) generated from the module table; the data-flow (`index.ts` -> registry -> `installAll` -> `scan`/`log`); and the four disabled modules with why they are off. Keep prose natural, not comment-dense.
- [ ] **Step 2: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "docs: add architecture guide"
```

### Task 43: CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

- [ ] **Step 1:** Write `CLAUDE.md` prefixed with the required Claude Code header. Include: build/watch/typecheck/test commands (pnpm); how to load the agent (`frida -U -f <pkg> -l _agent.js`); the module contract and how to add a new module (create `agent/modules/<id>.ts`, default-export `DecloakerModule`, register in `agent/modules/index.ts` in dispatch order); the logging severity convention and the G-THIS/G-TRACE porting invariants; the flag/RPC model. Do not restate obvious practices.
- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add CLAUDE.md guidance"
```

### Task 44: README quickstart

**Files:**
- Modify: `README.md`

- [ ] **Step 1:** Expand `README.md` with: what the suite is; prerequisites (Frida 17, pnpm, an Android device/emulator); `pnpm install && pnpm run build`; load command; a short table of the most useful flags and RPC toggles (`setbypass`, `setdump`, `enable`/`disable`, `list`, `addtarget`); and a pointer to `ARCHITECTURE.md`.
- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: expand README with build and usage quickstart"
```

### Task 45: Original source disposition

**Files:**
- Move or remove: `decloaker.js`

- [ ] **Step 1:** Once parity is confirmed, ask the user whether to (a) move `decloaker.js` to `legacy/decloaker-v28.js` for reference, or (b) delete it. Do not delete without confirmation.
- [ ] **Step 2:** Apply the chosen action and commit (`chore: retire monolithic decloaker.js`).

---

## Self-Review

**Spec coverage:**
- Build/toolchain (spec 1, 10) -> Task 1. Java bridge -> Task 10, Protocol step 4.
- Directory layout (spec 3) -> Tasks 3-13 (core/filters/config/types/registry).
- Module contract + registry (spec 4) -> Task 3 (type), Task 13 (registry/dispatch).
- Config/flag model + RPC (spec 5) -> Task 4, Task 13.
- Logging standard (spec 6) -> Task 6 (severity table, quiet filter, grammar).
- Filter engine: single-pass + retune (spec 7) -> Task 12 (matcher), Task 11 (lexicon + retune gate).
- Module inventory (spec 8) -> Phase D table (all 27, active + disabled, tags, ranges).
- Broken-hook repair, shipped disabled (spec 9) -> Tasks 37-40.
- Behavior preservation + parity (spec 12) -> Task 41.
- Docs (spec 11) -> Tasks 42-44.

**Placeholder scan:** module-port tasks reference exact source line ranges + the analysis-derived gotchas rather than fabricated code, because they are a mechanical port of an in-repo source file governed by the Porting Protocol. Pure-logic tasks (3-13) contain complete code and real tests. No "TBD"/"add error handling"/"similar to Task N" hand-waving remains.

**Type consistency:** `scan(source, value, traceCb?)` returns `string | false` and is consumed consistently; `log.<level>(tag, headline, fields?, trace?)` signature is stable across logger, matcher, and modules; `DecloakerModule`/`Config`/`IC`/`TraceThunk` are defined once in `types.ts` and imported everywhere.

**Open item carried to execution:** the shipped defaults for `activeBypass` and `targetModules` (Task 4 note) and the lexicon retune list (Task 12 gate) both require a user decision at execution time; both are flagged with STOP/NOTE gates rather than silently chosen.
