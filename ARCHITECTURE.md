# Architecture

`android-decloaker-suite` is a Frida 17 agent for Android app analysis. It installs
native and Java hooks that detect - and, when active bypass is enabled, spoof - the
anti-analysis, anti-debug, root/emulator, packer, crypto, network-C2, and
behavioral-IPC cloaking that evasive apps use. The agent is a modular TypeScript
rewrite of a single 5,962-line script (`decloaker.js`, "Sigma Decloaker V28"),
compiled to one bundle with `frida-compile`. Detection coverage and bypass semantics
are preserved from that source; the rewrite changes structure, not behavior.

## Directory layout

```
agent/
  index.ts            entry point: banner + installAll() inside setImmediate
  config.ts           the mutable Config object (compile-time defaults)
  rpc.ts              rpc.exports: live behavior + per-module toggles
  types.ts            DecloakerModule, Config, IC, LogLevel, TraceThunk
  globals.d.ts        ambient decls (console) the Frida runtime provides
  core/               shared, module-agnostic helpers
    logger.ts         leveled/tagged/colored output + quietSetup gating
    dedup.ts          bounded "already seen this signature" cache
    backtrace.ts      fuzzy native backtrace + target-scope filtering
    memory.ts         fault-safe reads, hex/magic preview, payload dump
    java.ts           frida-java-bridge re-export + Java byte[] converters
    attach.ts         safeAttachDetect: dedup'd detect-only native hook
  filters/
    lexicon.ts        categorized detection tokens -> one capture-group regex
    matcher.ts        scan(): the single-pass hot path
  modules/
    index.ts          registry (dispatch order) + installAll() dispatcher
    native/           14 pure-native hook modules (libc/syscall/memory)
    jni/              4 ART/JNI runtime-bridge modules (libart + JNIEnv vtable)
    java/             8 frida-java-bridge modules (Java API hooks)
    unity/            1 il2cpp module
```

Tests live in `tests/` (Vitest, pure-logic only) and are excluded from the
`frida-compile` bundle. `_agent.js` is the build artifact (gitignored).

## Data flow

`index.ts` runs inside `setImmediate`, prints the banner, then calls `installAll()`
(`modules/index.ts`). `installAll()`:

1. `seedModuleFlags()` copies each module's `enabledByDefault` into `config.modules[id]`,
   never clobbering a flag a prior RPC call already set.
2. It walks `registry` in order, skips any module whose environment gate is not ready,
   and calls each remaining `install()` inside a `try/catch` so one failure cannot abort
   the rest.

At runtime, a hooked function's handler reads the relevant string/buffer and calls
`scan(source, value, traceCb?)` (`filters/matcher.ts`). `scan` runs the value against the
compiled lexicon regex; on a match it dedups by signature and emits a `log.detect` line.
Modules that actively spoof do so in place, gated on `config.activeBypass`, and announce
it with `log.bypass`.

```
index.ts -> installAll() -> registry[].install()
                                 |
   hooked fn -> handler -> scan(value) -> matcher/lexicon -> log.detect
                        \-> (activeBypass) spoof in place -> log.bypass
```

## The module contract

Every hook module default-exports a `DecloakerModule` (`agent/types.ts`):

```ts
interface DecloakerModule {
  id: string;              // kebab-case, matches the filename
  tag: string;             // primary log tag
  description: string;
  enabledByDefault: boolean;
  requires?: "java" | "il2cpp";
  install(): void;         // performs the hooking; called once by the dispatcher
}
```

A module is inert until it is imported and pushed into `registry` in `modules/index.ts`.
Registry order reproduces the original `setImmediate` dispatch order.

`requires` is an environment gate. `requires: "java"` means the module only does Java-bridge
hooking (which throws without a VM), so the dispatcher skips it until `Java.available` is
true. Modules whose environment can appear *late* are not hard-gated: `unity-il2cpp` keeps
`requires: "il2cpp"` as documentation but installs unconditionally and runs its own 500ms
poll for `libil2cpp.so`, because Unity maps that library after process start. A module that
mixes native and Java hooks (`java-state-debug`) declares no `requires` and guards only its
Java section internally, so its native hooks still install on a VM-less process.

## Config and flags

`config` (`agent/config.ts`) is a single mutable object read live at call time - never cached
at install. Compile-time defaults are observe-first.

| flag | default | effect |
|------|---------|--------|
| `activeBypass` | `false` | when true, modules spoof/mutate instead of only observing |
| `dumpPayloads` | `false` | dump decrypted/unpacked buffers to `dumpDir` |
| `dumpDir` | `/data/local/tmp` | where dumps are written |
| `fullBacktrace` | `false` | print full native backtraces instead of a 5-frame head |
| `truncateHex` | `false` | shrink large hex previews to first/last 8 bytes |
| `quietSetup` | `true` | suppress the green `[+]` setup-confirmation lines |
| `hookMemoryProtection` | `false` | enable mprotect/mmap/munmap/remap hooks in memory-unpacking |
| `targetModules` | `[]` | when non-empty, only report hits whose caller is in these ELFs |
| `modules` | `{}` | per-module enable/disable, seeded from each `enabledByDefault` |

## RPC surface

`rpc.exports` (`agent/rpc.ts`) lets the Frida host mutate `config` live:

- `setbypass(bool)` - toggle `activeBypass` (deliberately defeat cloaking)
- `setdump(bool)` - toggle payload dumping
- `setfulltrace(bool)`, `settruncatehex(bool)`, `setquiet(bool)` - output verbosity
- `addtarget(elf)` / `cleartargets()` - scope analysis to specific loaded modules
- `enable(id)` / `disable(id)` - flip one module's flag
- `enableonly(...ids)` - enable exactly the listed modules, disable the rest
- `list()` - return and print every module's id, tag, and effective state

Per-module toggles and behavior flags take effect on the next hooked call; a module toggled
before `installAll()` runs is honored (its `enabledByDefault` will not overwrite the choice).

## Logging grammar

One leveled pipeline (`agent/core/logger.ts`) owns the visual grammar. Legacy ad-hoc colors
are not preserved; every line is emitted at its semantic level, and the level fixes the
marker and color:

| level | marker | color | meaning | gated? |
|-------|--------|-------|---------|--------|
| `detect` | `[!]` | red | a detection fired | no |
| `bypass` | `[BYPASS]` | red | an active spoof/mutation happened | no |
| `dump` | `[DUMP]` | purple | a payload buffer is being dumped | no |
| `setup` | `[+]` | green | a hook installed successfully | yes (`quietSetup`) |
| `warn` | `[-]` | yellow | a recoverable problem (hook failed, target absent) | no |
| `info` | `[*]` | cyan | status/confirmation | no |

`log.detect`/`log.bypass`/`log.dump` take optional `[label, value]` field rows; `log.detect`
also takes a preformatted backtrace. `log.once(sig, fn)` runs `fn` only the first time a
signature is seen.

## Filter engine

`filters/lexicon.ts` holds the detection vocabulary as categorized token arrays (Frida/root/
emulator/packer/DCL/network-C2/etc.), plus `BENIGN_FILTERS` (framework namespaces whose
callers are ignored) and `SPOOF_STRINGS`/`pathIsSpoofable` for the bypass paths. All tokens
compile into one `TARGET_REGEX` with a single capture group around the alternation, and a
`CANON_BY_LOWER` map for canonical casing.

`filters/matcher.ts` `scan(source, value, traceCb?)` is the hot path. A single
`TARGET_REGEX.exec()` yields both the matched token and its index in one pass (the legacy code
ran a regex test followed by a separate ~90-token indexOf loop). It applies the benign-caller
filter, dedups by `token|value-prefix|backtrace` signature, and emits one `log.detect` per new
signature. The trace callback is lazy - it is only invoked when a match actually needs a
backtrace.

## Module reference

Registry order (= original dispatch order). `dflt` is `enabledByDefault`; `req` is the
`requires` gate. `*` marks the four disabled modules.

| # | id | tag | dflt | req | what it hooks |
|---|-----|-----|------|-----|---------------|
| 1 | unity-il2cpp | UNITY CRYPTO | true | il2cpp (self-poll) | il2cpp C# crypto: Convert.FromBase64String, AES set_Key/set_IV, RijndaelManagedTransform.TransformFinalBlock |
| 2 | native-file-io | FILE-IO | true | - | libc open/openat/fopen/access/faccessat/stat family + __system_property_get; anti-analysis path detector; errno spoof bypass |
| 3 | deep-execution | EXEC | true | - | execve, ptrace, readlink, readlinkat |
| 4 | raw-syscalls | SYSCALL | true | - | raw syscall() dispatcher: path-arg scan + PTRACE_TRACEME detect/bypass |
| 5* | library-loading | DLOPEN | false | - | dlopen/android_dlopen_ext/dlsym/getenv (detect-only) |
| 6* | java-native-loaders | NATIVE LOAD | false | java | System/Runtime load & loadLibrary + loaded-module memory scan |
| 7 | system-properties | SYS-PROP | true | - | libc __system_property_get (ro.*/gsm.*) + emulator-tell spoof |
| 8 | java-dcl | DCL | true | java | DexClassLoader/PathClassLoader/InMemoryDexClassLoader constructors |
| 9 | java-evasion | TELEPHONY | true | java | Settings.Secure/Global, TelephonyManager, SensorManager, BatteryManager, Intent extras |
| 10 | network-traffic | NETWORK | true | - | SSL_read/SSL_write (libssl/libjavacrypto) + libc send/recv family |
| 11* | strings-native | CModule | false | - | CModule over strcpy/strcat/sprintf/snprintf + strstr stability guard |
| 12 | libart | JNI | true | - | libart RegisterNatives, FindClass |
| 13 | jni-env | JNIEnv table | true | java | JNIEnv vtable: GetMethodID, GetStaticMethodID, NewStringUTF, GetStringUTFChars |
| 14 | jni-extended | JNI | true | java | extended JNIEnv vtable: string/byte regions, Call* families, DefineClass, exceptions |
| 15 | art-dex-loaders | ART-DEX | true | - | in-memory dex loaders, DexFile_openDexFileNative, JNI_OnLoad, dlopen re-enumeration |
| 16 | file-content | FILE-CONTENT | true | - | file read/mmap content scanning; anti-debug/anti-frida artifact reads |
| 17 | fs-recon | FS-RECON | true | - | opendir/readdir, mount-table (getmntent) and stat reconnaissance |
| 18 | crypto-java | CRYPTO | true | java | javax.crypto Cipher/SecretKeySpec/IvParameterSpec/GCMParameterSpec, Base64, gzip |
| 19 | crypto-native | CRYPTO | true | - | libcrypto EVP_* encrypt/decrypt/cipher update+final; key/IV preview |
| 20 | memory-unpacking | MEM-UNPACK | true | - | memfd_create (always) + mprotect/mmap/munmap/remap (hookMemoryProtection) |
| 21 | reflection | REFLECTION | true | java | Method.invoke, Class.forName, ClassLoader.loadClass, Constructor.newInstance |
| 22 | anti-debug-native | ANTI-DEBUG | true | - | fork/clone, prctl, pthread_create, timing checks; anti-debug bypass |
| 23 | property-modern | PROP-MODERN | true | - | __system_property_find/read/read_callback (NativeCallback trampolines) |
| 24 | net-c2-native | C2 CONNECT | true | - | connect, getaddrinfo, gethostbyname (sockaddr + DNS parsing) |
| 25 | net-c2-java | NET-C2 | true | java | URL/HttpURLConnection/WebView, TLS pinning + TrustManager (bypass) |
| 26 | behavior-ipc | BEHAVIOR-IPC | true | java | SMS, Accessibility, ContentResolver, exec, PackageManager, ActivityManager, IPC, Clipboard |
| 27* | java-state-debug | ANTI-DEBUG | false | - | Debug/VMDebug debugger checks, SharedPreferences, native sqlite3 (unconditional) |

## The four disabled modules

These ship `enabledByDefault: false` because in the original tool they destabilized targets.
They are ported and compile-clean; a user enables each with `rpc.enable("<id>")` for manual
testing on a specific sample.

- **library-loading** - hooks dlopen/dlsym/android_dlopen_ext/getenv. These are extremely
  high-frequency symbol-resolution paths; attaching to all of them adds enough overhead to
  destabilize some apps. (The lower-frequency file/loader paths it would also catch are
  already covered by `native-file-io` and `art-dex-loaders`.)
- **java-native-loaders** - hooks System/Runtime library loading and scans each newly loaded
  module's memory. Scanning system libraries on load is expensive and can break framework
  startup; kept off until scoped to a target ELF.
- **strings-native** - a CModule instrumenting strcpy/strcat/sprintf/snprintf. In-process C
  instrumentation of these ubiquitous libc calls is powerful but risky; it also carries a
  known stability guard around strstr.
- **java-state-debug** - Debug/VMDebug/SharedPreferences hooks plus native sqlite3
  instrumentation. The native SQLite hooks install unconditionally (they need no Java VM);
  the module stays off by default because the combined surface was flagged unstable in the
  original tool.
