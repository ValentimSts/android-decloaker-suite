// Ported from legacy decloaker.js safeAttachDetect (lines 1236-1259), plus its
// module-private _detectAttached dedupe cache (line 1234).
//
// Shared native detection-attach helper used by fs-recon (active) and
// library-loading (disabled). Detection-only path/string hook (never spoofs):
// for high-frequency functions where an active bypass would break the app
// (dlopen/dlsym/getenv), we only observe and match.

import { getExportSafe, readStrSafe } from "./memory";
import { isTargetCaller, getNativeBacktrace } from "./backtrace";
import { scan } from "../filters/matcher";
import { log } from "./logger";
import type { IC } from "../types";

// Dedup set of already-attached export addresses, keyed by resolved pointer
// address string. dlopen/android_dlopen_ext/dlsym resolve to the SAME
// function in both libdl.so and libc.so (libc re-exports them), so
// per-module attaching would otherwise double-hook one function (duplicate
// alerts + double overhead on a symbol-resolution path).
const _detectAttached: Record<string, true> = {};

export function safeAttachDetect(moduleName: string, funcName: string, argIndex: number): void {
  const ptrAddress = getExportSafe(moduleName, funcName);
  if (!ptrAddress) return;
  const addrKey = ptrAddress.toString();
  if (_detectAttached[addrKey]) return; // already hooked this exact function via another module
  _detectAttached[addrKey] = true;
  try {
    Interceptor.attach(ptrAddress, {
      onEnter: function (this: IC, args) {
        if (!isTargetCaller(this.returnAddress)) return;
        const s = readStrSafe(args[argIndex]);
        if (!s) return;
        const ctx = this.context;
        scan(funcName, s, () => getNativeBacktrace(ctx));
      },
    });
    log.setup(funcName, "Hooked (detect): " + funcName);
  } catch (e: any) {
    log.warn(funcName, "Failed to hook " + funcName + ": " + e.message);
  }
}
