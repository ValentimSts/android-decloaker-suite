# android-decloaker-suite

A Frida 17 agent that "decloaks" evasive Android apps. It hooks native and Java
APIs to detect - and optionally spoof - anti-analysis, anti-debug, root/emulator,
packer, crypto, network-C2, and behavioral-IPC cloaking. Built as a modular
TypeScript agent compiled with `frida-compile`.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the module contract and full
reference.

## Usage

```bash
pnpm install
pnpm run build                                  # -> _agent.js
frida -U -f com.example.target -l _agent.js     # spawn (use -n to attach)
```

The agent starts observe-only (reports detections, mutates nothing). Toggle
behavior live from the Frida REPL via `rpc.exports`:

| toggle | effect |
|--------|--------|
| `setbypass(true)` | actively spoof/defeat cloaking instead of only observing |
| `setdump(true)` | dump decrypted/unpacked payloads to disk |
| `enable("id")` / `disable("id")` | flip one module on or off |
| `enableonly("id", ...)` | run only the listed modules |
| `list()` | show every module's id, tag, and state |

Requires Frida 17 (with a matching `frida-server` on the device), pnpm, and a
rooted device or emulator.
