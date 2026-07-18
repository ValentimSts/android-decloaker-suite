// Ported from legacy decloaker.js hookPropertyModern (lines 4318-4396), plus its
// module-private PROP_CB_TRAMPOLINES registry and makePropReadTrampoline helper
// (lines 4286-4316).
//
// Detection-only. __system_property_get is already hooked elsewhere (native-file-io's
// safeAttachIO); this module covers the MODERN libc property APIs that malware uses to
// sidestep that single hook when fingerprinting emulator/root state (ro.kernel.qemu,
// ro.build.tags, ro.debuggable, ...):
//
//   - __system_property_find(name)                 name = arg0, returns prop_info*
//   - __system_property_read(pi, name_out, val_out) pi = arg0, out bufs filled AFTER call
//   - __system_property_read_callback(pi, cb, cookie) name/value delivered to cb(cookie,name,value,serial)
//
// Gating: these are not hot like read/mmap/clock_gettime/connect, but they still fire per
// property probe. We gate every hook with isTargetCaller(this.returnAddress) (module
// allowlist) and let scan()'s own dedup keep repeated identical (name,value) pairs silent.
// No spoofing here (detection-only), so no activeBypass / pathIsSpoofable path is taken.

import { log } from "../core/logger";
import { getExportSafe, readStrSafe } from "../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../core/backtrace";
import { scan } from "../filters/matcher";
import type { IC, DecloakerModule } from "../types";

const TAG = "PROP-MODERN";

type PropReadCallback = NativeCallback<"void", ["pointer", "pointer", "pointer", "uint32"]>;

// Trampoline registry for __system_property_read_callback: maps the ORIGINAL callback
// pointer (as a string key) to a persistent NativeCallback that inspects (name, value) then
// forwards to the original. This MUST stay a module-level registry, not install()-local
// scratch: the native property system holds onto the trampoline's pointer for as long as the
// app keeps using that callback, and a GC'd NativeCallback means that pointer starts
// dereferencing freed memory on the next property read - a process crash. Keeping the map at
// module scope also ensures a given original callback is only ever wrapped once.
const PROP_CB_TRAMPOLINES: Record<string, PropReadCallback> = {};

function makePropReadTrampoline(origCbPtr: NativePointer): PropReadCallback {
  const key = origCbPtr.toString();
  const existing = PROP_CB_TRAMPOLINES[key];
  if (existing) return existing;

  // Original signature: void cb(void *cookie, const char *name, const char *value, uint32_t serial)
  const origFn = new NativeFunction(origCbPtr, "void", ["pointer", "pointer", "pointer", "uint32"]);

  const trampoline: PropReadCallback = new NativeCallback(
    function (cookie, namePtr, valuePtr, serial) {
      try {
        const name = readStrSafe(namePtr);
        const value = readStrSafe(valuePtr);
        // No Interceptor CpuContext inside a NativeCallback, so no reliable backtrace here;
        // omit the trace thunk (scan treats it as unavailable) and combine name+value so a
        // match on either field is caught (e.g. name "ro.kernel.qemu" or value "goldfish").
        const combined = name + "=" + value;
        scan("__system_property_read_callback", combined);
      } catch (e) {}
      // Always forward to the real callback so the app's property read is unaffected.
      // The original returns void, so do not propagate a return value.
      origFn(cookie, namePtr, valuePtr, serial);
    },
    "void",
    ["pointer", "pointer", "pointer", "uint32"]
  );

  PROP_CB_TRAMPOLINES[key] = trampoline;
  return trampoline;
}

const mod: DecloakerModule = {
  id: "property-modern",
  tag: TAG,
  description:
    "Detects the modern libc property-read APIs (find/read/read_callback) used to bypass __system_property_get hooks",
  enabledByDefault: true,
  install() {
    // --- __system_property_find(name) : name = arg0, returns prop_info* -----------------
    const findPtr = getExportSafe("libc.so", "__system_property_find");
    if (findPtr) {
      try {
        Interceptor.attach(findPtr, {
          // onEnter shares no state across calls here, but stays a classic function so
          // `this` is the per-call InvocationContext (arrow would break returnAddress/context).
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const name = readStrSafe(args[0]);
            if (!name) return;
            const ctx = this.context;
            scan("__system_property_find", name, () => getNativeBacktrace(ctx));
          },
        });
        log.setup(TAG, "Hooked (detect): __system_property_find");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook __system_property_find: " + e.message);
      }
    }

    // --- __system_property_read(pi, name_out, val_out) --------------------------------
    // pi = arg0, name_out = arg1, val_out = arg2. The out buffers are only populated AFTER
    // the call, so capture the pointers on enter and read/match them on leave. The function
    // returns the value length (>0) on success and <=0 when nothing was written, so only read
    // the out buffers on a positive return to avoid logging stale/garbage buffer contents.
    const readPtr = getExportSafe("libc.so", "__system_property_read");
    if (readPtr) {
      try {
        Interceptor.attach(readPtr, {
          // onEnter/onLeave share this.skip/namePtr/valuePtr/ctx via the per-call
          // InvocationContext, so both MUST stay classic functions.
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.namePtr = args[1];
            this.valuePtr = args[2];
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip) return;
            if (retval.toInt32() <= 0) return;
            const name = readStrSafe(this.namePtr);
            const value = readStrSafe(this.valuePtr);
            if (!name && !value) return;
            const ctx = this.ctx;
            const combined = name + "=" + value;
            scan("__system_property_read", combined, () => getNativeBacktrace(ctx));
          },
        });
        log.setup(TAG, "Hooked (detect): __system_property_read");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook __system_property_read: " + e.message);
      }
    }

    // --- __system_property_read_callback(pi, cb, cookie) ------------------------------
    // pi = arg0, cb = arg1, cookie = arg2. The name/value are handed to
    // cb(cookie, name, value, serial). We replace the caller's callback (arg1) with a
    // persistent trampoline that inspects (name, value) then forwards to the original, so the
    // property name/value are resolved even on this modern path.
    const readCbPtr = getExportSafe("libc.so", "__system_property_read_callback");
    if (readCbPtr) {
      try {
        Interceptor.attach(readCbPtr, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const origCb = args[1];
            if (origCb.isNull()) return;
            try {
              args[1] = makePropReadTrampoline(origCb);
            } catch (e: any) {
              log.warn(TAG, "__system_property_read_callback trampoline failed: " + e.message);
            }
          },
        });
        log.setup(TAG, "Hooked (detect): __system_property_read_callback");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook __system_property_read_callback: " + e.message);
      }
    }
  },
};

export default mod;
