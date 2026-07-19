#!/usr/bin/env python3
"""Host-side loader for the Android Decloaker Frida agent.

Loads the compiled agent into a target process, wires the agent's rpc.exports
toggles from command-line flags, and keeps the session alive until interrupted.

Active bypass is ON by default: the agent itself ships observe-only, and this
loader opts you into spoofing. Pass --observe to load without bypass.

Usage:
    python androidDecloaker-loader.py -f com.example.app                # spawn, bypass on
    python androidDecloaker-loader.py -n com.example.app --observe      # attach, observe only
    python androidDecloaker-loader.py -f com.example.app --dump --target libfoo.so
"""

import argparse
import glob
import os
import sys


def load_frida():
    """Import frida lazily so --help and arg errors work without it installed."""
    try:
        import frida
        return frida
    except ImportError:
        sys.stderr.write(
            "error: the 'frida' Python package is required.\n"
            "       install it with: pip install frida-tools\n"
        )
        sys.exit(1)


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="androidDecloaker-loader.py",
        description="Load the Android Decloaker agent and drive its RPC toggles.",
    )

    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "-f", "--spawn", metavar="PKG",
        help="spawn PKG and install hooks before it runs (recommended)",
    )
    target.add_argument(
        "-n", "--attach", metavar="PKG",
        help="attach to an already-running PKG (name or pid)",
    )

    p.add_argument(
        "-l", "--agent", metavar="PATH",
        help="path to the agent .js (default: auto-discover "
             "androidDecloaker-*.js next to this script)",
    )
    p.add_argument(
        "-D", "--device", metavar="ID",
        help="Frida device id (default: the USB device)",
    )

    mode = p.add_argument_group("mode")
    mode.add_argument(
        "--observe", action="store_true",
        help="observe only; do NOT enable active bypass (bypass is on by default)",
    )
    mode.add_argument(
        "--dump", action="store_true",
        help="dump decrypted/unpacked payloads to disk (rpc setdump)",
    )
    mode.add_argument(
        "--full-trace", action="store_true",
        help="capture full native backtraces (rpc setfulltrace)",
    )
    mode.add_argument(
        "--verbose", action="store_true",
        help="show the [+] setup lines the agent hides by default (rpc setquiet false)",
    )
    mode.add_argument(
        "--truncate-hex", action="store_true",
        help="truncate long hex dumps (rpc settruncatehex)",
    )
    mode.add_argument(
        "--target", metavar="ELF", action="append", default=[], dest="targets",
        help="scope analysis to this native module; repeatable (rpc addtarget)",
    )
    mode.add_argument(
        "--enable-only", metavar="IDS",
        help="run only these module ids, comma-separated (rpc enableonly)",
    )

    return p.parse_args(argv)


def resolve_agent(path):
    """Return the agent .js path, auto-discovering next to this script if unset."""
    if path:
        if not os.path.isfile(path):
            sys.exit("error: agent file not found: " + path)
        return path

    here = os.path.dirname(os.path.abspath(__file__))
    matches = sorted(glob.glob(os.path.join(here, "androidDecloaker-*.js")))
    if not matches:
        sys.exit(
            "error: no --agent given and no androidDecloaker-*.js found next to "
            "the loader.\n"
            "       download androidDecloaker-<version>.js from the Releases page, "
            "or pass -l/--agent PATH."
        )
    if len(matches) > 1:
        sys.stderr.write(
            "[!] multiple agent files found; using " + os.path.basename(matches[-1]) +
            " (override with -l/--agent)\n"
        )
    return matches[-1]


def get_device(frida, device_id):
    if device_id:
        return frida.get_device(device_id)
    return frida.get_usb_device()


def get_exports(script):
    # frida >= 16 exposes exports_sync; older builds use exports.
    return getattr(script, "exports_sync", None) or script.exports


def on_message(message, data):
    mtype = message.get("type")
    if mtype == "send":
        print(message.get("payload"))
    elif mtype == "error":
        sys.stderr.write((message.get("stack") or message.get("description") or str(message)) + "\n")


def apply_toggles(script, args):
    """Drive rpc.exports. Scoping and module selection first, bypass last."""
    ex = get_exports(script)

    if args.enable_only:
        ids = [s.strip() for s in args.enable_only.split(",") if s.strip()]
        if ids:
            ex.enableonly(*ids)
    for elf in args.targets:
        ex.addtarget(elf)

    if args.verbose:
        ex.setquiet(False)
    if args.truncate_hex:
        ex.settruncatehex(True)
    if args.full_trace:
        ex.setfulltrace(True)
    if args.dump:
        ex.setdump(True)

    # Enable bypass last, once scoping and module selection are in place.
    if not args.observe:
        ex.setbypass(True)


def main(argv):
    args = parse_args(argv)
    agent_path = resolve_agent(args.agent)
    with open(agent_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    frida = load_frida()
    try:
        device = get_device(frida, args.device)
    except Exception as exc:
        sys.exit("error: could not reach a Frida device: " + str(exc))

    pid = None
    spawned = False
    try:
        if args.spawn:
            print("[*] spawning " + args.spawn)
            pid = device.spawn([args.spawn])
            spawned = True
            session = device.attach(pid)
        else:
            target = int(args.attach) if args.attach.isdigit() else args.attach
            print("[*] attaching to " + str(target))
            session = device.attach(target)
    except Exception as exc:
        sys.exit("error: could not open the target: " + str(exc))

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    apply_toggles(script, args)
    mode = "observe only" if args.observe else "bypass ON"
    print("[*] loaded " + os.path.basename(agent_path) + " (" + mode + ")")

    if spawned:
        device.resume(pid)

    print("[*] press Ctrl+C to detach.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
    print("\n[*] detached.")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(130)
