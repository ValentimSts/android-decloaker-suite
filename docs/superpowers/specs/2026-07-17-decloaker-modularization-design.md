# Decloaker Suite Modularization - Design Spec

Date: 2026-07-17
Status: Approved (design), pending implementation plan
Author: ValentimSts

## 1. Overview

`decloaker.js` ("Sigma Decloaker V28") is a single 5,962-line ES5 Frida script
for Android malware analysis. It installs ~27 categories of native and Java
hooks that detect and (optionally) actively bypass anti-analysis, anti-debug,
root/emulator, packer, crypto, network C2, and behavioral-IPC cloaking.

This project refactors that monolith into a modular, standardized, Frida 17
TypeScript agent built with `frida-compile`, without changing what the tool
detects or how it bypasses cloaking.

### Goals

- Break the monolith into small, single-purpose modules that can be read,
  edited, and tested independently.
- Adopt the modern Frida 17 toolchain: TypeScript + `frida-compile`, with the
  Java bridge bundled from `frida-java-bridge`.
- Make every hook category individually toggleable via granular flags, at
  compile time (defaults) and at runtime (RPC).
- Standardize logging into one leveled, tagged pipeline with a single visual
  grammar.
- Optimize the hot-path string matcher and retune the detection lexicon.
- Produce living documentation (`ARCHITECTURE.md`, `CLAUDE.md`, README).

### Non-goals

- Changing detection coverage or active-bypass semantics (beyond the agreed
  lexicon retune, which is signed off separately).
- Enabling the four currently-broken hooks in the shipped default config.
- Adding new detection capabilities or new target platforms.

## 2. Constraints and decisions

Decided during brainstorming:

1. Language/build: **TypeScript + `frida-compile`** (the Frida 17 standard).
2. Output shape: **one bundled agent** driven by **granular flags**.
3. Scope: **reorganize + standardize + repair the four broken hooks**, but ship
   the repaired hooks **disabled by default** for manual testing.
4. Filters: **optimize matching AND retune the lexicon** (retune list signed off
   before it lands).

Frida 17 facts that shape the design (verified against the Frida docs):

- `frida-compile agent/index.ts -o _agent.js -c` is the standard build; `-w`
  gives watch mode. `frida-create -t agent` scaffolds the project.
- As of Frida 17 the Java bridge is no longer in the GumJS runtime. It must be
  installed via npm (`frida-java-bridge`) and imported as
  `import Java from "frida-java-bridge"`. Every Java-touching module depends on
  this, so bundling it is mandatory.

## 3. Target architecture

Single agent, compiled from a module tree, dispatched by a registry.

```
android-decloaker-suite/
  package.json            # frida-compile build/watch scripts, deps
  tsconfig.json
  _agent.js               # build output (git-ignored); this is what you inject
  README.md               # quickstart
  ARCHITECTURE.md         # full structure + per-module docs + data flow
  CLAUDE.md               # guidance for future Claude sessions
  agent/
    index.ts              # banner, RPC wiring, dispatch loop over the registry
    config.ts             # all flags + compile-time defaults (mutable at runtime)
    types.ts              # DecloakerModule, LogLevel, LexiconEntry, ...
    core/
      logger.ts           # leveled/tagged logger; owns ANSI palette, quiet, dedup
      dedup.ts            # bounded ALERT_HISTORY seen-cache (markSeen)
      backtrace.ts        # getNativeBacktrace / formatBacktrace / isTargetCaller
      memory.ts           # getExportSafe / readStrSafe / hexPreview / payloadMagic / dumpBuffer
      java.ts             # Java bridge helpers: perform wrapper, jbytes* converters, availability gate
    filters/
      lexicon.ts          # categorized TARGET_STRINGS, BENIGN_FILTERS, SPOOF_STRINGS
      matcher.ts          # single-pass matcher + scan() (was checkAndLog)
    modules/
      index.ts            # registry: ordered DecloakerModule[]
      <one file per hook category>
```

### 3.1 Data flow

1. `index.ts` runs under `setImmediate`, prints the banner, and reports
   `activeBypass` + `targetModules` state via the logger.
2. It walks the ordered registry from `modules/index.ts`. For each module:
   skip if disabled in `config`, skip with a `[-]` note if its `requires`
   environment is unavailable (e.g. `java`, `il2cpp`), otherwise call
   `install()` inside a `try/catch` so one failing module cannot abort the rest.
3. Modules attach interceptors. On a hooked event they call
   `filters.matcher.scan(...)` and/or the `logger`, which dedupes via
   `core/dedup` and formats output with the standard grammar. Active-bypass
   paths read live `config` flags so runtime RPC toggles take effect mid-session.

## 4. Module contract and registry

Every hook category is a module with a uniform shape:

```ts
export interface DecloakerModule {
  id: string;                     // "crypto-native" - also its config flag key
  tag: string;                    // "CRYPTO-NATIVE" - log tag
  description: string;
  enabledByDefault: boolean;      // false for the four repaired-but-risky hooks
  requires?: "java" | "il2cpp";   // env gate; skipped with a logged reason if unmet
  install(): void;
}
```

`modules/index.ts` exports an ordered `registry: DecloakerModule[]`. Order
preserves the current dispatch order so install-time side effects and log
ordering match today's behavior.

## 5. Config and flag model

One `config` object, seeded at compile time in `config.ts`, mutable at runtime:

- Global behavior: `activeBypass`, `dumpPayloads`, `dumpDir`, `fullBacktrace`,
  `truncateHex`, `quietSetup`, `hookMemoryProtection`, `targetModules[]`.
- Per-module enable map: `modules[id] = boolean`, seeded from each module's
  `enabledByDefault`.
- Modules read live behavior flags rather than capturing them at install, so
  `setbypass`/`setdump` mid-session work.

RPC surface (superset of today's), all delegating to `config`:

- Existing: `addtarget`, `cleartargets`, `setfulltrace`, `setbypass`, `setdump`,
  `setquiet`, `settruncatehex`.
- New: `enable(id)`, `disable(id)`, `enableonly(...ids)`, `list()` (prints every
  module id + tag + enabled state).

The four repaired hooks and `hookMemoryProtection` default OFF and are turned on
only via `enable(id)` / the corresponding flag.

## 6. Logging standard

A leveled logger replaces the fragile `console.log` monkey-patch that currently
implements `quiet` by string-sniffing for `[+]`.

| Level  | Marker      | Color  | Hidden by quiet |
|--------|-------------|--------|-----------------|
| detect | `[!]`       | red    | never           |
| bypass | `[BYPASS]`  | red    | never           |
| dump   | `[DUMP]`    | purple | never           |
| setup  | `[+]`       | green  | yes             |
| warn   | `[-]`       | yellow | no              |
| info   | `[*]`       | cyan   | no              |

Standard multi-line grammar, identical across modules:

```
[!] [TAG] <headline>
    -> <field>: <value>
    -> Source Backtrace:
    <frames>
```

`quiet` becomes a real level filter (drops `setup`), not a string match. Dedup
is integrated via `logger.once(signature, fn)` backed by `core/dedup`.

## 7. Filter engine

### 7.1 Matching performance

Today `checkAndLog` runs two scans of every candidate string on the hot path: a
`TARGET_REGEX.test(value)` to decide "does anything match", then an ~90-token
`indexOf` loop to find which token matched and where. The regex already knows
both. The refactor collapses this to a single `TARGET_REGEX.exec(value)` using a
capture group: the match text and `match.index` come from one scan, and the
context window derives from `match.index`. The regex is precompiled once. A
`Set` backs any exact-match fast paths. This also removes a latent bug where the
loop's first-match token can differ from the regex's actual match.

### 7.2 Lexicon retune

`lexicon.ts` keeps the categorized token groups but flags false-positive-prone
broad tokens for reconsideration (candidates: `timezone`, `.bundle`, `organic`,
`mcc`, `mnc`, `adb_enabled`). The concrete keep/drop/narrow list is presented for
sign-off during implementation; detection coverage is not changed silently.
`SPOOF_STRINGS` (the narrow active-bypass allowlist) and `BENIGN_FILTERS` move
across unchanged unless explicitly retuned.

## 8. Module inventory (current -> new)

Active modules (dispatched today; `enabledByDefault: true`):

| New module             | Source function(s)                         | Tag           | Notes |
|------------------------|--------------------------------------------|---------------|-------|
| native-file-io         | `safeAttachIO` family + inline open/stat/access attaches, `libcClose`, `setErrnoENOENT`, `hookNativeFileIO` | FILE-IO | active-bypass file existence spoofing + openat recon |
| system-properties      | `hookSystemProperties`                      | SYS-PROP      | prop spoofing |
| deep-execution         | `hookDeepExecution`                          | EXEC          | |
| raw-syscalls           | `hookRawSyscalls`                            | SYSCALL       | syscall() evasion of libc hooks |
| java-dcl               | `hookJavaDCL`                                | DCL           | requires: java |
| java-evasion           | `hookJavaEvasionAPIs`                        | JAVA-EVASION  | requires: java |
| network-traffic        | `hookNetworkTraffic`                         | NET           | |
| libart                 | `hookLibart`                                 | ART           | |
| jni-env                | `hookJNIEnv` + `hookJniMethod` helper        | JNI           | |
| jni-extended           | `hookJNIEnvExtended`                          | JNI-EXT       | |
| art-dex-loaders        | `hookArtDexLoaders`                           | ART-DEX       | |
| file-content           | `hookFileContent`                            | FILE-CONTENT  | |
| fs-recon               | `hookFsRecon`                                | FS-RECON      | |
| crypto-java            | `hookCryptoJava`                             | CRYPTO-JAVA   | requires: java |
| crypto-native          | `hookCryptoNative`                           | CRYPTO-NATIVE | |
| memory-unpacking       | `hookMemoryUnpacking`                        | MEM-UNPACK    | mprotect/mmap gated by hookMemoryProtection |
| reflection             | `hookReflection`                             | REFLECTION    | requires: java |
| anti-debug-native      | `hookAntiDebugNative`                         | ANTI-DBG      | |
| property-modern        | `hookPropertyModern`                          | PROP-MODERN   | |
| net-c2-native          | `hookNetworkC2Native`                         | NET-C2        | |
| net-c2-java            | `hookNetworkC2Java`                           | NET-C2-JAVA   | requires: java |
| behavior-ipc           | `hookBehaviorIPC`                             | BEHAVIOR-IPC  | requires: java |
| unity-il2cpp           | `hookUnityIL2CPP` + il2cpp helpers            | UNITY         | requires: il2cpp; late-load wait encapsulated in install() |

Disabled modules (repair-attempted, `enabledByDefault: false`):

| New module             | Source function(s)                          | Tag         | Why disabled |
|------------------------|---------------------------------------------|-------------|--------------|
| library-loading        | `hookLibraryLoading`                         | DLOPEN      | dlopen/dlsym/getenv hooks destabilize the target |
| java-native-loaders    | `hookJavaNativeLoaders` + `scanModuleMemory` | NATIVE-LOAD | breaks with system libs; `scanModuleMemory` is only reachable here |
| strings-native         | `hookStringsNative`                           | STRINGS     | native strcmp/strstr hooks destabilize the target |
| java-state-debug       | `hookJavaStateAndDebug` + `hookSqliteNative`  | JAVA-STATE  | requires: java; `hookSqliteNative` is only reachable here |

Two functions are currently dead code because their only caller is a disabled
hook: `scanModuleMemory` (called from `hookJavaNativeLoaders`) and
`hookSqliteNative` (called from `hookJavaStateAndDebug`). They move into the
respective disabled modules and stay disabled.

## 9. Broken-hook repair handling

Each of the four disabled hooks becomes a normal module with
`enabledByDefault: false`. Repairs are attempted and documented in-module (why
it broke, what changed), but the shipped registry leaves them off. The user
enables each via `enable(id)` to test manually against a real sample.

## 10. Build and tooling

- Deps: dev `frida-compile`, `@types/frida-gum`; runtime `frida-java-bridge`
  (bundled into `_agent.js`).
- `package.json` scripts: `build` (`frida-compile agent/index.ts -o _agent.js -c`),
  `build:dev` (sourcemaps, no compress), `watch` (`-w`).
- Load: `frida -U -f <pkg> -l _agent.js` or `frida -U -p <pid> -l _agent.js`.
- Package manager: **pnpm** (`pnpm-lock.yaml`). Use `pnpm install` / `pnpm run build`.

## 11. Documentation deliverables

- `ARCHITECTURE.md`: directory layout, module contract, per-module purpose and
  hooked surface, data flow, logging/flag conventions.
- `CLAUDE.md`: build/run/watch commands, module contract, logging + flag
  conventions, where to add a new module.
- `README.md`: quickstart (build, load, common flags/RPC).

## 12. Behavior preservation and acceptance criteria

- Same detections, same active-bypass logic, same RPC behavior, same late
  `libil2cpp.so` wait (moved into the unity module's `install()`).
- Enabling all default modules reproduces today's dispatched hook set.
- `_agent.js` compiles cleanly and loads under Frida 17 without runtime errors on
  a smoke target.
- Intentional changes only: logging pipeline, single-pass matcher, retuned
  tokens (signed off), per-module gating, `try/catch` install isolation.

## 13. Risks and open questions

- `frida-java-bridge` typings: confirm whether `@types` are needed or the package
  ships its own; resolve at implementation.
- Exact lexicon retune list requires user sign-off before landing.
- Repaired hooks cannot be validated without a device/sample; they ship disabled.

## 14. Out of scope

- New detection features or platforms.
- CI, automated device tests, or a test harness (no runtime test surface without
  a device).
- Enabling the four repaired hooks by default.
