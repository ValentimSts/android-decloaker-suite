# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Frida 17 agent for Android app analysis ("decloaking"): it installs native and
Java hooks that detect - and, when active bypass is on, spoof - anti-analysis,
anti-debug, root/emulator, packer, crypto, network-C2, and behavioral-IPC
cloaking. The codebase is an in-progress refactor of a single 5,962-line ES5
script (`decloaker.js`, "Sigma Decloaker V28") into a modular TypeScript agent
compiled with `frida-compile`. Detection tokens and bypass semantics are meant
to be preserved across the port, not changed.

The original monolith is retained at `legacy/decloaker-v28.js` as the
**source-of-truth reference for the port** (module files cite exact line ranges
from it). The port is complete and verified at parity; the legacy file is kept
for historical comparison, not active development.

## Commands

```bash
pnpm install              # package manager is pnpm (pnpm-lock.yaml) - never npm/yarn
pnpm run build            # frida-compile agent/index.ts -> _agent.js (minified, compressed)
pnpm run build:dev        # same, unminified
pnpm run watch            # rebuild on change
pnpm run typecheck        # tsc --noEmit (strict) - the real gate for hook modules
pnpm test                 # vitest run (all tests)
pnpm exec vitest run tests/matcher.test.ts   # a single test file
pnpm exec vitest run -t "name of test"        # a single test by name
```

`_agent.js` is the build artifact (gitignored). Load it into a target with the
Frida host tooling (`frida -U -f <pkg> -l _agent.js`, etc.).

## Architecture

Entry point `agent/index.ts` runs inside `setImmediate`, prints the banner, then
calls `installAll()`. Everything hangs off a single mutable `config` object and
an ordered module registry.

- **`agent/config.ts`** - compile-time defaults for the `Config` object.
  `activeBypass` defaults OFF (observe-only); enable at runtime via RPC.
  Mutated live by `rpc.ts`.
- **`agent/rpc.ts`** - `rpc.exports` toggles callable from the Frida host:
  behavior flags (`setbypass`, `setdump`, `setfulltrace`, `setquiet`,
  `settruncatehex`), target scoping (`addtarget`/`cleartargets`), and per-module
  control (`enable`/`disable`/`enableonly`/`list`) over the registry.
- **`agent/core/`** - shared helpers: `logger` (leveled/tagged/colored output +
  `quietSetup` gating), `dedup` (bounded seen-signature cache, cap 5000),
  `backtrace` (fuzzy native backtrace + `isTargetCaller` scoping), `memory`
  (fault-safe `getExportSafe`/`readStrSafe`/`hexPreview`/`payloadMagic`), `java`
  (the `frida-java-bridge` re-export + Java byte[] <-> hex/printable/native
  converters), `attach` (`safeAttachDetect`, a dedup'd detect-only native hook).
- **`agent/filters/`** - `lexicon` (categorized detection tokens compiled into
  one capture-group `TARGET_REGEX`, plus `BENIGN_FILTERS` and spoof strings)
  and `matcher` (`scan(source, value, traceCb?)` - the hot path; one
  `regex.exec()` yields both the matched token and its index, then dedups by
  signature and emits a `log.detect`).
- **`agent/modules/`** - ~27 self-contained hook modules (one detection
  category each) plus `index.ts`, the registry + dispatcher.

### The module contract

Every hook module default-exports a `DecloakerModule` (`agent/types.ts`):

```ts
const mod: DecloakerModule = {
  id, tag, description,
  enabledByDefault,      // repaired-but-risky hooks ship false
  requires?,             // "java" | "il2cpp" - environment gate
  install() { /* Interceptor.attach / Java.perform hooks */ },
};
export default mod;
```

A module does nothing until it is **pushed into `registry`** in
`agent/modules/index.ts`. Registry order must reproduce the original
`setImmediate` dispatch order from `decloaker.js`. `installAll()`:
1. `seedModuleFlags()` - fills `config.modules[id]` from each `enabledByDefault`
   (never clobbering a flag already set via RPC),
2. iterates enabled modules, skips any whose `requires` environment is not ready
   *right now* (this is a one-shot check - a module needing a late-loading lib
   like `libil2cpp.so` must implement its own wait/poll inside `install()`),
3. calls each `install()` inside try/catch so one failure cannot abort the rest.

## Non-obvious invariants (read before editing modules)

These are the traps that silently break a Frida agent - the compiler will not
catch most of them:

- **`this`-binding:** `Interceptor` `onEnter`/`onLeave` handlers and Java
  `.implementation` bodies MUST be classic `function` expressions, never arrow
  functions. Frida rebinds `this` (the per-call `InvocationContext` or Java
  instance) on each invocation; an arrow shares one `this` across every call.
  When a handler stashes fields on `this`, type it as `IC`
  (`InvocationContext & Record<string, any>` from `agent/types.ts`).
- **Lazy backtrace:** pass `scan()` a thunk that captures a local, never `this`.
  Copy `this.context` into `const ctx` in the handler, then pass
  `() => getNativeBacktrace(ctx)`. Referencing `this` inside the thunk is wrong.
- **Ambient vs real imports:** `frida-gum` types (`NativePointer`,
  `InvocationContext`, `Process`, `Memory`, `Interceptor`, `Thread`, `File`,
  `CpuContext`, ...) are **ambient globals** - use them directly, do NOT
  `import` from `"frida-gum"` (it has no exports and fails to resolve).
  `frida-java-bridge` IS a real module - Java code must
  `import Java from "frida-java-bridge"` (re-exported from `agent/core/java`).
- **Frida 17 API:** static `Memory.readPointer` was removed; use instance
  methods (`ptr.readPointer()`, `ptr.readByteArray()`). Preserve
  `Process.pointerSize === 8` branches and byte-order assumptions exactly.
- **ASCII only** in all source, comments, identifiers, and string literals
  (including log output). Use `->` in log text, never a Unicode arrow.
- Preserve per-iteration `let`/`const` bindings in loops that build `Interceptor`
  closures, or every closure captures the final value.

## Testing model

Vitest covers **pure logic only** (matcher, lexicon, config, dedup, backtrace,
logger, dispatch selection). Hook `install()` bodies are NOT unit-tested; their
gate is `pnpm run typecheck` + `pnpm run build`. Tests live in `tests/` (outside
the `tsconfig` include). `vitest.config.ts` aliases `frida-java-bridge` to a
stub (`tests/stubs/`) because the real package runs GumJS-only top-level code on
import; the real build is unaffected. `tests/setup.ts` provides minimal Frida
global stand-ins (e.g. `fakePtr`).

## Project state

Refactor in progress on `chore/modularize-decloaker-suite`. Core infra (config,
core/, filters/, registry, RPC) is committed. The ~27 module files are drafted
but currently **untracked and not all wired into `registry`** - drafting a
module and registering it in `agent/modules/index.ts` are separate steps. The
plan and design spec live in `docs/superpowers/`.
