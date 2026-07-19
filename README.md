# android-decloaker-suite

A Frida 17 agent that "decloaks" evasive Android apps. It hooks native and Java
APIs to detect - and optionally spoof - anti-analysis, anti-debug, root/emulator,
packer, crypto, network-C2, and behavioral-IPC cloaking. Built as a modular
TypeScript agent compiled with `frida-compile`.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the module contract and full
reference.

## Prebuilt agent (no build required)

Each [release](https://github.com/ValentimSts/android-decloaker-suite/releases)
ships a compiled agent, so you can skip the toolchain. Download the two assets:

- `androidDecloaker-<version>.js` - the compiled agent.
- `androidDecloaker-loader.py` - an optional host-side loader.

Load it straight through Frida (observe-only; toggle live via the REPL, see
[Toggling behavior](#toggling-behavior)):

```bash
frida -U -f com.example.target -l androidDecloaker-<version>.js
```

Or use the loader, which wires the toggles for you and enables active bypass by
default (pass `--observe` to only observe):

```bash
python androidDecloaker-loader.py -f com.example.target             # spawn, bypass on
python androidDecloaker-loader.py -n com.example.target --observe   # attach, observe only
python androidDecloaker-loader.py -f com.example.target --dump --target libfoo.so
```

The loader needs the `frida` Python package (`pip install frida-tools`) and the
agent file beside it (or a `-l/--agent` path). The device's `frida-server` must
match the Frida version the release was built against (Frida 17).

## Build from source

```bash
pnpm install
pnpm run build                                  # -> _agent.js
frida -U -f com.example.target -l _agent.js     # spawn (use -n to attach)
```

Requires Frida 17 (with a matching `frida-server` on the device), pnpm, and a
rooted device or emulator.

## Toggling behavior

The agent starts observe-only (reports detections, mutates nothing). Toggle
behavior live from the Frida REPL via `rpc.exports` (the loader exposes the same
controls as command-line flags):

| toggle | effect |
|--------|--------|
| `setbypass(true)` | actively spoof/defeat cloaking instead of only observing |
| `setdump(true)` | dump decrypted/unpacked payloads to disk |
| `enable("id")` / `disable("id")` | flip one module on or off |
| `enableonly("id", ...)` | run only the listed modules |
| `list()` | show every module's id, tag, and state |

## Cutting a release

Releases are built by CI ([`.github/workflows/release.yml`](.github/workflows/release.yml)).
Bump `version` in `package.json`, then push a matching tag:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The workflow verifies the tag equals the `package.json` version, builds the
agent, and publishes `androidDecloaker-<version>.js` plus the loader to a release
titled `Android Decloaker v<version>`. A tag that disagrees with `package.json`
fails the build.
