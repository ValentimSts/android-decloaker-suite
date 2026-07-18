// Ported from legacy decloaker.js hookRawSyscalls (lines 1272-1329).
//
// Raw syscall() dispatcher. Malware often calls syscall(__NR_openat/ptrace/...) directly to
// bypass libc-export hooks. Only arm64 and x86_64 (the common Android ABIs) are covered;
// inlined SVC/int 0x80 instructions still evade this and would need Stalker instrumentation.

import { config } from "../../config";
import { log } from "../../core/logger";
import { getExportSafe, readStrSafe } from "../../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../../core/backtrace";
import { scan } from "../../filters/matcher";
import type { IC, DecloakerModule } from "../../types";

const TAG = "SYSCALL";

const mod: DecloakerModule = {
  id: "raw-syscalls",
  tag: TAG,
  description: "Hooks the raw syscall() dispatcher to catch path/exec syscalls issued directly and spoof raw PTRACE_TRACEME",
  enabledByDefault: true,
  install() {
    const sysPtr = getExportSafe("libc.so", "syscall");
    if (!sysPtr) return;

    // Per-arch syscall numbers. arm64 (asm-generic) has no legacy non-*at file syscalls.
    // x86_64 still exposes the legacy open/stat/lstat/access/readlink, which malware can
    // issue directly on an emulator.
    const TABLES: Record<string, Record<string, number>> = {
      arm64: { openat: 56, faccessat: 48, newfstatat: 79, statx: 291, readlinkat: 78, execve: 221, ptrace: 117 },
      x64: {
        openat: 257, faccessat: 269, newfstatat: 262, statx: 332, readlinkat: 267, execve: 59, ptrace: 101,
        open: 2, stat: 4, lstat: 6, access: 21, readlink: 89,
      },
    };
    const table = TABLES[Process.arch];
    if (!table) {
      log.warn(TAG, "Raw syscall hook: unsupported arch " + Process.arch);
      return;
    }
    const byNum: Record<number, string> = {};
    Object.keys(table).forEach((k) => { byNum[table[k]] = k; });

    // When routed through syscall(), all kernel arguments shift by one (args[0] is the number).
    // Path position in args[] (args[0] is the syscall number). The *at family takes the path as
    // kernel arg1 (args[2]); execve and the legacy non-*at calls take it as kernel arg0 (args[1]).
    const PATH_AT: Record<string, number> = {
      openat: 2, faccessat: 2, newfstatat: 2, statx: 2, readlinkat: 2, execve: 1,
      open: 1, stat: 1, lstat: 1, access: 1, readlink: 1,
    };

    Interceptor.attach(sysPtr, {
      onEnter: function (this: IC, args) {
        this.sysName = null;
        if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
        this.skip = false;

        const name = byNum[args[0].toInt32()];
        if (!name) return;
        this.sysName = name;

        if (name === "ptrace") {
          this.isTraceme = args[1].toInt32() === 0; // PTRACE_TRACEME == 0
          return;
        }
        const idx = PATH_AT[name];
        if (idx !== undefined) {
          const path = readStrSafe(args[idx]);
          const ctx = this.context;
          scan("syscall:" + name, path, () => getNativeBacktrace(ctx));
        }
      },
      onLeave: function (this: IC, retval) {
        if (this.skip || this.sysName !== "ptrace" || !this.isTraceme) return;
        log.detect(TAG, "PTRACE_TRACEME via raw syscall detected!");
        if (config.activeBypass) {
          log.bypass(TAG, "Spoofing raw ptrace success (Returning 0).");
          retval.replace(ptr("0x0"));
        }
      },
    });
    log.setup(TAG, "Hooked raw syscall dispatcher (" + Process.arch + ")");
  },
};

export default mod;
