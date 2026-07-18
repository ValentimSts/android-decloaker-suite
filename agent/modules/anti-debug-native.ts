// Ported from legacy decloaker.js hookAntiDebugNative (lines 3990-4266), plus
// its module-private _antiDbgSeen dedup helper and the ANTIDBG_SIGNALS /
// PR_SET_NAME / PR_GET_NAME / PR_SET_DUMPABLE / TIMING_SAMPLING /
// TIMING_SAMPLE_EVERY / _timingCounts constants.
//
// Native process-level anti-debug primitives: self-debug forks, prctl
// dumpable/thread-name games, watchdog pthread_create, anti-debug signal
// handler installs, liveness-probe kill(sig=0), inotify self-tamper watches,
// and an optional sampled counter for the (extremely hot) clock_gettime /
// gettimeofday timing-check primitives. Detection-only except for the prctl
// PR_GET_NAME thread-name spoof, which is gated on config.activeBypass.

import { config } from "../config";
import { log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { getExportSafe, readStrSafe } from "../core/memory";
import { getNativeBacktrace, formatBacktrace, isTargetCaller } from "../core/backtrace";
import { scan } from "../filters/matcher";
import { pathIsSpoofable } from "../filters/lexicon";
import type { IC, DecloakerModule } from "../types";

const TAG = "ANTI-DEBUG";

// Signal numbers commonly abused by anti-debug handlers (installing a handler for these lets a
// sample "catch" a debugger's SIGTRAP/SIGILL or crash-on-attach and take an evasive branch).
const ANTIDBG_SIGNALS: Record<number, string> = { 4: "SIGILL", 5: "SIGTRAP", 11: "SIGSEGV" };

// prctl options we care about (from <sys/prctl.h>): PR_SET_DUMPABLE flips ptrace-attachability;
// PR_SET_NAME/PR_GET_NAME are used to read/rename threads to scan for/hide "gum-js-loop", "gmain",
// "pool-frida" watchdog thread names.
const PR_SET_NAME = 15;
const PR_GET_NAME = 16;
const PR_SET_DUMPABLE = 4;

// gettimeofday/clock_gettime are EXTREMELY hot (called on nearly every frame / syscall wrapper).
// CHOICE: we do NOT attach a per-call logging Interceptor to them - that would flood the console
// and add no real signal, since a single timing read is not itself a detection. Instead we keep a
// cheap sampled counter behind a default-off flag; when TIMING_SAMPLING is enabled we only emit one
// aggregated line every TIMING_SAMPLE_EVERY calls. Left off by default so timing hooks cost nothing.
const TIMING_SAMPLING = false;
const TIMING_SAMPLE_EVERY = 100000;
const _timingCounts: Record<string, number> = { clock_gettime: 0, gettimeofday: 0 };

// Backtrace-free dedup for the anti-debug alerts. Reuses the shared hasSeen/markSeen dedup store.
// Returns true if this signature has already been reported (caller should skip); false the first
// time (and records it).
function _antiDbgSeen(sig: string): boolean {
  if (hasSeen(sig)) return true;
  markSeen(sig);
  return false;
}

const mod: DecloakerModule = {
  id: "anti-debug-native",
  tag: TAG,
  description:
    "Hooks native process-level anti-debug primitives: forks, prctl, signal handlers, liveness probes",
  enabledByDefault: true,
  install() {
    // ---- self-debug / process forks: fork / vfork / __clone / clone ----
    // Malware forks a child to ptrace(PTRACE_ATTACH) its own parent (a debugger can only attach
    // once), or spawns a watchdog process. Not hot enough to need content gating; module-gated.
    ["fork", "vfork", "__clone", "clone"].forEach(function (fn) {
      const p = getExportSafe("libc.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
            this.skip = false;
            // Compute the backtrace once and reuse it for both the dedup key and the log
            // (the original computed it twice per event).
            const bt = formatBacktrace(getNativeBacktrace(this.context));
            const sig = "antidbg-fork|" + fn + "|" + bt;
            if (_antiDbgSeen(sig)) return;
            log.detect(TAG, "Self-debug/watchdog fork primitive: " + fn + "()", undefined, bt);
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: " + fn);
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- prctl: dumpable flip + thread-name read/spoof ----
    // Gated: only logs the specific options of interest, so ordinary prctl traffic is ignored.
    // prctl(int option, unsigned long arg2, ...) -> option=args[0], arg2=args[1].
    const prctlPtr = getExportSafe("libc.so", "prctl");
    if (prctlPtr) {
      try {
        Interceptor.attach(prctlPtr, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
            this.skip = false;
            this.opt = args[0].toInt32();
            this.arg1 = args[1];
            this.nameBuf = null;
            this.ctx = this.context;

            if (this.opt === PR_SET_DUMPABLE && this.arg1.toInt32() === 0) {
              // dumpable=0 blocks ptrace attach and /proc/pid/mem reads (anti-debug).
              const bt = formatBacktrace(getNativeBacktrace(this.ctx));
              const sig = "antidbg-prctl-dumpable|" + bt;
              if (_antiDbgSeen(sig)) return;
              log.detect(TAG, "prctl(PR_SET_DUMPABLE, 0) - blocking debugger attach.", undefined, bt);
            } else if (this.opt === PR_SET_NAME) {
              // Renaming a thread - malware hides its watchdog, or renames to check names.
              const nm = readStrSafe(this.arg1, 16); // thread names are capped at 16 bytes (TASK_COMM_LEN)
              // Capture context into a local: inside the scan trace closure `this` is NOT the
              // Interceptor context (scan calls the closure bare).
              const ctx = this.ctx;
              scan("prctl(PR_SET_NAME)", nm, () => getNativeBacktrace(ctx));
            } else if (this.opt === PR_GET_NAME) {
              // Buffer is written by the kernel; capture it and scan on leave for frida
              // thread-name artifacts (gum-js-loop / gmain / pool-frida).
              this.nameBuf = this.arg1;
            }
          },
          onLeave: function (this: IC, retval) {
            if (this.skip) return;
            if (this.opt === PR_GET_NAME && this.nameBuf && !this.nameBuf.isNull()) {
              const nm = readStrSafe(this.nameBuf, 16);
              const ctx = this.ctx;
              const match = scan("prctl(PR_GET_NAME)", nm, () => getNativeBacktrace(ctx));
              // Spoof only when the resolved thread name is a genuine frida artifact and
              // active bypass is on; overwrite the returned name so the scan comes back clean.
              if (match && config.activeBypass && pathIsSpoofable(nm)) {
                try {
                  this.nameBuf.writeUtf8String("main");
                  log.bypass(TAG, "Spoofed frida thread name '" + nm + "' -> 'main'.");
                } catch (e) {}
              }
            }
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: prctl (DUMPABLE/SET_NAME/GET_NAME)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook prctl: " + e.message);
      }
    }

    // ---- pthread_create: resolve start routine -> DebugSymbol (watchdog threads) ----
    // pthread_create(thread, attr, start_routine, arg) -> start_routine=args[2].
    const pthreadPtr = getExportSafe("libc.so", "pthread_create");
    if (pthreadPtr) {
      try {
        Interceptor.attach(pthreadPtr, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const startRoutine = args[2];
            const bt = formatBacktrace(getNativeBacktrace(this.context));
            let sym = "";
            try { sym = DebugSymbol.fromAddress(startRoutine).toString(); } catch (e) {}
            const sig = "antidbg-pthread|" + startRoutine + "|" + sym;
            if (_antiDbgSeen(sig)) return;
            log.detect(
              TAG,
              "pthread_create start_routine: " + startRoutine + (sym ? " (" + sym + ")" : ""),
              undefined,
              bt,
            );
            // Also run the symbol string through the lexicon (e.g. a routine in libjiagu.so).
            if (sym) scan("pthread_create routine", sym);
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: pthread_create");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook pthread_create: " + e.message);
      }
    }

    // ---- sigaction / signal: anti-debug handlers for SIGTRAP/SIGILL/SIGSEGV ----
    // Gated to only the anti-debug signal numbers so ordinary signal setup is ignored.
    // sigaction(int signum, ...) / signal(int signum, ...) -> signum=args[0].
    ["sigaction", "signal", "bsd_signal", "sysv_signal"].forEach(function (fn) {
      const p = getExportSafe("libc.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const signum = args[0].toInt32();
            const name = ANTIDBG_SIGNALS[signum];
            if (!name) return; // only report the anti-debug signals
            const bt = formatBacktrace(getNativeBacktrace(this.context));
            const sig = "antidbg-signal|" + fn + "|" + name + "|" + bt;
            if (_antiDbgSeen(sig)) return;
            log.detect(TAG, fn + "() installing handler for " + name + " (" + signum + ")", undefined, bt);
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: " + fn);
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- kill / tgkill / tkill: sig==0 liveness probe (a debugger/analysis parent still alive?) ----
    // Gated to sig==0 only; real signal delivery is left alone to avoid flooding.
    // kill(pid, sig) -> sig=args[1]; tgkill(tgid, tid, sig) -> sig=args[2]; tkill(tid, sig) -> sig=args[1].
    const KILL_FUNCS: { fn: string; sigIdx: number }[] = [
      { fn: "kill", sigIdx: 1 },
      { fn: "tgkill", sigIdx: 2 },
      { fn: "tkill", sigIdx: 1 },
    ];
    KILL_FUNCS.forEach(function (cfg) {
      const p = getExportSafe("libc.so", cfg.fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const signum = args[cfg.sigIdx].toInt32();
            if (signum !== 0) return; // only the sig==0 liveness probe is of interest
            const target = args[0].toInt32();
            const bt = formatBacktrace(getNativeBacktrace(this.context));
            const sig = "antidbg-kill0|" + cfg.fn + "|" + target + "|" + bt;
            if (_antiDbgSeen(sig)) return;
            log.detect(TAG, cfg.fn + "(pid/tid=" + target + ", sig=0) liveness probe.", undefined, bt);
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: " + cfg.fn + " (sig==0)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + cfg.fn + ": " + e.message);
      }
    });

    // ---- getppid: parent-pid checks (is the parent zygote, or an analysis harness?) ----
    // Low frequency; dedup on backtrace so a polling loop only prints once.
    const getppidPtr = getExportSafe("libc.so", "getppid");
    if (getppidPtr) {
      try {
        Interceptor.attach(getppidPtr, {
          onEnter: function (this: IC) {
            if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
            this.skip = false;
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip) return;
            const ppid = retval.toInt32();
            const bt = formatBacktrace(getNativeBacktrace(this.ctx));
            const sig = "antidbg-getppid|" + bt;
            if (_antiDbgSeen(sig)) return;
            log.detect(TAG, "getppid() -> " + ppid + " (parent-process identity check).", undefined, bt);
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: getppid");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook getppid: " + e.message);
      }
    }

    // ---- inotify_add_watch: watching a path (self-tamper / frida-file detection) ----
    // inotify_add_watch(fd, pathname, mask) -> pathname=args[1].
    const inotifyPtr = getExportSafe("libc.so", "inotify_add_watch");
    if (inotifyPtr) {
      try {
        Interceptor.attach(inotifyPtr, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const watched = readStrSafe(args[1]);
            if (!watched) return;
            const ctx = this.context;
            const match = scan("inotify_add_watch", watched, () => getNativeBacktrace(ctx));
            if (!match) {
              // Even non-lexicon paths are worth a single low-noise note (dedup by path).
              const sig = "antidbg-inotify|" + watched;
              if (_antiDbgSeen(sig)) return;
              log.detect(TAG, "inotify_add_watch watching: " + watched);
            }
          },
        });
        log.setup(TAG, "Hooked Anti-Debug: inotify_add_watch");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook inotify_add_watch: " + e.message);
      }
    }

    // ---- clock_gettime / gettimeofday: EXTREMELY hot - default-OFF sampled counter only ----
    // See TIMING_SAMPLING note above: no per-call logging. When enabled, emits one aggregated
    // line every TIMING_SAMPLE_EVERY calls; when disabled (default) these are not attached at all.
    if (TIMING_SAMPLING) {
      ["clock_gettime", "gettimeofday"].forEach(function (fn) {
        const p = getExportSafe("libc.so", fn);
        if (!p) return;
        try {
          Interceptor.attach(p, {
            onEnter: function () {
              // No isTargetCaller / backtrace here - both are too expensive for this
              // call rate. Just a bounded modulo counter; net cost is a single increment.
              _timingCounts[fn]++;
              if (_timingCounts[fn] % TIMING_SAMPLE_EVERY === 0) {
                log.info("TIMING", fn + " sampled count: " + _timingCounts[fn]);
              }
            },
          });
          log.setup(TAG, "Hooked (sampled) timing: " + fn);
        } catch (e: any) {
          log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
        }
      });
    } else {
      log.setup(
        TAG,
        "Timing hooks (clock_gettime/gettimeofday) SKIPPED - too hot; enable TIMING_SAMPLING to sample.",
      );
    }
  },
};

export default mod;
