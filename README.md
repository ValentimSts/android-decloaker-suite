# android-decloaker-suite

A Frida 17 agent for Android app analysis ("decloaking"). It installs native and
Java hooks that detect - and, when active bypass is enabled, spoof - the
anti-analysis, anti-debug, root/emulator, packer, crypto, network-C2, and
behavioral-IPC cloaking that evasive apps use to hide from instrumentation.

The agent is a modular TypeScript rewrite of a single-file script ("Sigma
Decloaker V28"), compiled to one bundle with `frida-compile`. Detection coverage
and bypass semantics are preserved from that source. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the module contract, data flow, and a
per-module reference.

## Prerequisites

- [Frida](https://frida.re) 17 on the host, with a matching `frida-server`
  running on the device.
- An Android device or emulator, rooted or with a Frida gadget, and USB access.
- [pnpm](https://pnpm.io) (this repo pins pnpm via `pnpm-lock.yaml`; do not use
  npm or yarn).

## Build

```bash
pnpm install
pnpm run build        # frida-compile agent/index.ts -> _agent.js (minified)
```

Other scripts: `pnpm run build:dev` (unminified), `pnpm run watch` (rebuild on
change), `pnpm run typecheck` (strict tsc - the real gate for hook modules),
`pnpm test` (Vitest, pure-logic only).

## Run

Load the built `_agent.js` into a target process:

```bash
frida -U -f com.example.target -l _agent.js        # spawn
frida -U -n com.example.target -l _agent.js        # attach to running app
```

The agent starts observe-only: it reports detections but does not mutate the
app. Enable spoofing and other behavior live from the Frida REPL through
`rpc.exports`.

## Useful flags and RPC toggles

Call these on the session's `rpc.exports` (in the Frida REPL, `rpc.exports` is
the `%exports`/`e` object; from a host script it is `script.exports`):

| toggle | effect |
|--------|--------|
| `setbypass(true)` | turn on active bypass - modules spoof/mutate instead of only observing (deliberately defeats cloaking) |
| `setdump(true)` | dump decrypted/unpacked payload buffers to the dump dir |
| `setfulltrace(true)` | print full native backtraces instead of a short head |
| `settruncatehex(true)` | shrink large hex previews to first/last bytes |
| `setquiet(false)` | show the green `[+]` setup-confirmation lines |
| `addtarget("libfoo.so")` | scope reporting to hits whose caller is in this ELF |
| `cleartargets()` | clear all target scoping (report everything again) |
| `enable("id")` / `disable("id")` | flip one module on or off |
| `enableonly("id", ...)` | enable exactly the listed modules, disable the rest |
| `list()` | print every module's id, tag, and effective state |

Four modules ship disabled by default because they can destabilize a target
(`library-loading`, `java-native-loaders`, `strings-native`,
`java-state-debug`); enable each with `enable("<id>")` for manual testing. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the full flag model and module list.
