// Ported from legacy decloaker.js hookLibraryLoading (lines 1260-1267).
//
// Native library loading / symbol resolution and environment probes. Packers
// and second-stage payloads dlopen decrypted .so files without going through
// Java. All hooks here are the shared detection-only safeAttachDetect helper
// (../core/attach) - never spoofs, since dlopen/dlsym/getenv sit on such a
// hot, foundational path that an active bypass would very likely destabilize
// or crash the target under Frida on Android. SHIPS DISABLED BY DEFAULT:
// dlopen/dlsym/getenv are extremely high-frequency (every native lib load and
// every symbol lookup passes through them), so even passive interception here
// is risky enough (loader re-entrancy, JNI_OnLoad timing, perf overhead on a
// hot path) that it is opt-in only.

import { safeAttachDetect } from "../core/attach";
import type { DecloakerModule } from "../types";

const TAG = "DLOPEN";

const mod: DecloakerModule = {
  id: "library-loading",
  tag: TAG,
  description: "Detects native library loading and symbol/env probing via dlopen/dlsym/getenv",
  enabledByDefault: false,
  install() {
    // dlopen/android_dlopen_ext/dlsym resolve to the same function whether
    // reached via libdl.so or libc.so's re-export; safeAttachDetect's shared
    // _detectAttached cache collapses the duplicate attach automatically.
    ["libdl.so", "libc.so"].forEach(function (libName) {
      safeAttachDetect(libName, "dlopen", 0);
      safeAttachDetect(libName, "android_dlopen_ext", 0);
      safeAttachDetect(libName, "dlsym", 1);
    });
    safeAttachDetect("libc.so", "getenv", 0); // LD_PRELOAD, FRIDA_*, emulator env vars
  },
};

export default mod;
