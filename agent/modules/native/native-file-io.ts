// Ported from legacy decloaker.js hookNativeFileIO (lines 460-476), the active-bypass
// I/O trio libcClose/setErrnoENOENT/safeAttachIO (lines 856-949), and the safeAttachIO(...)
// call list from the setImmediate initializer (lines 5917-5931).
//
// Merges the openat anti-analysis detector with the active-bypass file-existence
// spoofer covering the full libc file I/O surface (open/openat/fopen/access/faccessat/
// __system_property_get and the stat/lstat/statx family) into one module.

import { config } from "../../config";
import { log } from "../../core/logger";
import { getExportSafe, readStrSafe } from "../../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../../core/backtrace";
import { scan } from "../../filters/matcher";
import { pathIsSpoofable } from "../../filters/lexicon";
import type { IC, DecloakerModule } from "../../types";

const TAG = "FILE-IO";

// Lazily-resolved libc helpers used to keep active bypass semantically correct.
// Tri-state: null = not yet looked up, false = lookup failed (don't retry), else the fn.
let closeFn: NativeFunction<number, [number]> | null | false = null;
let errnoLocFn: NativeFunction<NativePointer, []> | null | false = null;

function libcClose(fd: number): void {
  try {
    if (closeFn === null) {
      const p = getExportSafe("libc.so", "close");
      closeFn = p ? new NativeFunction(p, "int", ["int"]) : false;
    }
    if (closeFn) closeFn(fd);
  } catch (e) {}
}

function setErrnoENOENT(): void {
  try {
    if (errnoLocFn === null) {
      const p = getExportSafe("libc.so", "__errno_location");
      errnoLocFn = p ? new NativeFunction(p, "pointer", []) : false;
    }
    if (errnoLocFn) errnoLocFn().writeInt(2); // ENOENT
  } catch (e) {}
}

function safeAttachIO(moduleName: string, funcName: string, argIndex: number): void {
  const ptrAddress = getExportSafe(moduleName, funcName);
  if (!ptrAddress) return;
  try {
    Interceptor.attach(ptrAddress, {
      // onEnter/onLeave share per-call state via `this` (a fresh InvocationContext
      // per call), so both MUST stay classic functions - an arrow would collapse
      // that to one shared `this`.
      onEnter: function (this: IC, args) {
        if (!isTargetCaller(this.returnAddress)) {
          this.skip = true;
          return;
        }
        this.skip = false;
        this.pathStr = readStrSafe(args[argIndex]);
        this.args = args;
        this.ctx = this.context;
      },
      onLeave: function (this: IC, retval) {
        if (this.skip || !this.pathStr) return;
        const ctx = this.ctx;
        // Lazy backtrace thunk: capture the local `ctx` (never `this`) so the
        // matcher only pays for a backtrace when it actually reports a match.
        const match = scan(funcName, this.pathStr, () => getNativeBacktrace(ctx));

        // Detection fires on the full lexicon, but only spoof when the path itself contains
        // a narrow-allowlist artifact - never spoof legitimate paths on a broad token match.
        if (match && config.activeBypass && pathIsSpoofable(this.pathStr)) {
          log.bypass(TAG, "Spoofing Bypass for: " + funcName);

          let spoofVal = ptr("-1");

          if (funcName === "fopen") {
            // BUG (preserved): opens a real, empty file instead of returning NULL (0x0).
            // The export is guaranteed resolvable here - it's the very function we're
            // currently inside a hook for - so a fresh lookup can't legitimately fail.
            const fopenExport = getExportSafe("libc.so", "fopen")!;
            const fopenPtr = new NativeFunction(fopenExport, "pointer", ["pointer", "pointer"]);
            const devNull = Memory.allocUtf8String("/dev/null");
            const mode = Memory.allocUtf8String("r");
            spoofVal = fopenPtr(devNull, mode);
          } else if (funcName === "__system_property_get") {
            spoofVal = ptr("0x0");
            try {
              this.args[1].writeUtf8String("");
            } catch (e) {}
          } else if (funcName === "open" || funcName === "openat") {
            // open/openat return a real fd. If the call already succeeded, replacing
            // the return with -1 would leak the descriptor, so close it first, then
            // report ENOENT (set AFTER close, since close() clobbers errno).
            const realFd = retval.toInt32();
            if (realFd >= 0) {
              libcClose(realFd);
              setErrnoENOENT();
            }
          } else if (
            funcName === "stat" || funcName === "lstat" || funcName === "stat64" ||
            funcName === "lstat64" || funcName === "newfstatat" || funcName === "statx"
          ) {
            // stat family returns 0 on success; spoof to -1 and report ENOENT so callers
            // that check errno after a -1 (common in File.exists()/root checks) see a
            // consistent "file not found" rather than a stale errno.
            if (retval.toInt32() === 0) setErrnoENOENT();
          }

          // retval.replace is the InvocationReturnValue method (always available in
          // onLeave) - NOT Interceptor.replace.
          try {
            retval.replace(spoofVal);
          } catch (e: any) {
            log.warn(TAG, "Bypass error: " + e.message);
          }
        }
      },
    });
    log.setup(TAG, "Hooked I/O: " + funcName);
  } catch (e: any) {
    log.warn(TAG, "Failed to hook I/O " + funcName + ": " + e.message);
  }
}

function hookNativeFileIO(): void {
  const openatPtr = getExportSafe("libc.so", "openat");
  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter: function (this: IC, args) {
        const path = readStrSafe(args[1]);
        if (path && (path.indexOf("/proc/") !== -1 || path.indexOf("/sys/") !== -1 || path.indexOf("qemu") !== -1)) {
          log.detect(TAG, "openat detected anti-analysis read", [["Target", path]]);
        }
      },
    });
  }
  log.setup(TAG, "Hooked Native File I/O (openat)");
}

const mod: DecloakerModule = {
  id: "native-file-io",
  tag: TAG,
  description:
    "Hooks libc file I/O (open/openat/fopen/access/stat family) for path detection and active-bypass spoofing",
  enabledByDefault: true,
  install() {
    safeAttachIO("libc.so", "open", 0);
    safeAttachIO("libc.so", "openat", 1);
    safeAttachIO("libc.so", "fopen", 0);
    safeAttachIO("libc.so", "access", 0);
    safeAttachIO("libc.so", "faccessat", 1);
    safeAttachIO("libc.so", "__system_property_get", 0);

    // File-existence probing: the stat/lstat/statx family (common root/emulator existence
    // checks; Java File.exists() lowers to these, not access). Path arg is 0, *at variants 1.
    safeAttachIO("libc.so", "stat", 0);
    safeAttachIO("libc.so", "lstat", 0);
    safeAttachIO("libc.so", "stat64", 0);
    safeAttachIO("libc.so", "lstat64", 0);
    safeAttachIO("libc.so", "newfstatat", 1);
    safeAttachIO("libc.so", "statx", 1);

    // Second, un-gated openat hook: the anti-analysis /proc//sys//qemu detector,
    // which fires for ANY caller (no isTargetCaller gate), exactly as in the legacy.
    hookNativeFileIO();
  },
};

export default mod;
