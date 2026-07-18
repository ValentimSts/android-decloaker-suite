// Ported from legacy decloaker.js hookDeepExecution (lines 783-847).
//
// Process spawning, anti-debug (ptrace), and symlink-resolution hooks used
// by cloaking libs to (a) shell out to inspect their own environment, (b)
// detect a debugger via PTRACE_TRACEME, and (c) resolve /proc/self paths
// that leak the real package/process identity.

import { config } from "../config";
import { log } from "../core/logger";
import { getExportSafe, readStrSafe } from "../core/memory";
import { getNativeBacktrace, formatBacktrace, isTargetCaller } from "../core/backtrace";
import { scan } from "../filters/matcher";
import type { IC, DecloakerModule } from "../types";

const TAG = "EXEC";

const mod: DecloakerModule = {
  id: "deep-execution",
  tag: TAG,
  description: "Hooks execve, ptrace anti-debug, and readlink/readlinkat symlink resolution",
  enabledByDefault: true,
  install() {
    const execvePtr = getExportSafe("libc.so", "execve");
    if (execvePtr) {
      Interceptor.attach(execvePtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) return;
          const cmd = readStrSafe(args[0]);
          const argv = args[1];
          let fullCmd = cmd;
          if (!argv.isNull()) {
            fullCmd += " ";
            // Cap at 15 args - matches the legacy bound, plenty for a spoofed-cmd signature.
            for (let i = 1; i < 15; i++) {
              const argPtr = argv.add(i * Process.pointerSize).readPointer();
              if (argPtr.isNull()) break;
              fullCmd += readStrSafe(argPtr) + " ";
            }
          }
          const ctx = this.context;
          scan("execve", fullCmd, () => getNativeBacktrace(ctx));
        },
      });
      log.setup(TAG, "Hooked Process: execve");
    }

    const ptracePtr = getExportSafe("libc.so", "ptrace");
    if (ptracePtr) {
      Interceptor.attach(ptracePtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.skip = false;
          this.req = args[0].toInt32();
          // Stashed here so onLeave (same `this`, per Frida's invocation-scoped
          // InvocationContext) can build a backtrace from the call site.
          this.ctx = this.context;
        },
        onLeave: function (this: IC, retval) {
          if (this.skip) return;
          if (this.req === 0) {
            // req 0 == PTRACE_TRACEME.
            log.detect(
              TAG,
              "Anti-Debugging PTRACE_TRACEME detected!",
              undefined,
              formatBacktrace(getNativeBacktrace(this.ctx))
            );

            if (config.activeBypass) {
              log.bypass(TAG, "Spoofing ptrace success (Returning 0).");
              retval.replace(ptr("0x0"));
            }
          }
        },
      });
      log.setup(TAG, "Hooked Anti-Debug: ptrace");
    }

    // Local helper: readlink and readlinkat share this exact detect-only shape,
    // differing only in which export they hook and which arg holds the path.
    function attachReadlink(funcName: string, argIdx: number): void {
      const rlPtr = getExportSafe("libc.so", funcName);
      if (rlPtr) {
        Interceptor.attach(rlPtr, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const path = readStrSafe(args[argIdx]);
            const ctx = this.context;
            scan(funcName, path, () => getNativeBacktrace(ctx));
          },
        });
      }
    }
    attachReadlink("readlink", 0);
    attachReadlink("readlinkat", 1);
  },
};

export default mod;
