// Ported from legacy decloaker.js hookJavaNativeLoaders (lines 510-591) plus
// its helper scanModuleMemory (lines 477-504).
//
// Hooks the Java-side native-library entry points (System.load/loadLibrary and
// Runtime.load/loadLibrary). Every load is reported with a Java backtrace, and
// on a successful System.loadLibrary the freshly mapped .so is scanned in
// memory for embedded emulator/tooling strings (qemu_pipe, reqwest, substratum,
// ro.arch). loadLibrary is wrapped in a race-condition retry: an
// UnsatisfiedLinkError (typical when a packer is still dropping the .so) is
// caught, the thread sleeps 3s, and the load is retried once.
//
// REPAIR: the legacy source guarded the post-load scan with a bare
// `if (!isSystemLib) scanModuleMemory(libname)`, but `isSystemLib` was never
// defined - that line threw a ReferenceError at runtime, so the scan never ran.
// Here isSystemLib is a real check: a path under /system/ or /apex/, or a
// known-framework library basename.

import { Java, withJava } from "../core/java";
import { log } from "../core/logger";
import type { DecloakerModule } from "../types";

const TAG = "NATIVE LOAD";

// Framework/NDK library basenames we do not bother scanning after a load: they
// are shipped by the platform, not dropped by the app, so scanning them is pure
// noise. Compared against the normalized basename (no "lib" prefix, no ".so").
const SYSTEM_LIB_BASENAMES: string[] = [
  "monochrome",
  "webview",
  "android",
  "android_runtime",
  "art",
  "log",
  "c",
  "m",
  "dl",
  "z",
  "stdc++",
  "c++_shared",
  "jnigraphics",
  "OpenSLES",
  "GLESv2",
  "GLESv3",
  "EGL",
  "vulkan",
  "aaudio",
  "mediandk",
  "nativewindow",
  "binder_ndk",
  "icuuc",
  "icui18n",
];

// Suspicious byte patterns hunted for inside a freshly loaded library (same set
// and hex encodings as the legacy scanModuleMemory).
const SCAN_PATTERNS: { name: string; hex: string }[] = [
  { name: "QEMU Pipe", hex: "71 65 6d 75 5f 70 69 70 65" }, // qemu_pipe
  { name: "Rust Reqwest", hex: "72 65 71 77 65 73 74" }, // reqwest
  { name: "Substratum", hex: "73 75 62 73 74 72 61 74 75 6d" }, // substratum
  { name: "ro.arch string", hex: "72 6f 2e 61 72 63 68" }, // ro.arch
];

// Repair for the legacy undefined `isSystemLib` reference. True when the name is
// an absolute path into the system/apex partitions, or reduces to a known
// framework basename - in which case we skip the memory scan.
function isSystemLib(libname: string): boolean {
  if (!libname) return false;
  if (libname.indexOf("/system/") !== -1 || libname.indexOf("/apex/") !== -1) return true;

  let base = libname;
  const slash = base.lastIndexOf("/");
  if (slash !== -1) base = base.substring(slash + 1);
  if (base.startsWith("lib")) base = base.substring(3);
  if (base.endsWith(".so")) base = base.substring(0, base.length - 3);

  return SYSTEM_LIB_BASENAMES.indexOf(base) !== -1;
}

// Scan a just-loaded library's memory image for the embedded strings above.
// Ambient globals (Process/Memory) are only touched here, at call time from
// inside a hook - never at module import - so the module stays import-safe.
function scanModuleMemory(libName: string): void {
  // Convert a short name (e.g. "gdresourcekit") to its map name
  // ("libgdresourcekit.so").
  let actualName = libName;
  if (!actualName.startsWith("lib")) actualName = "lib" + actualName;
  if (!actualName.endsWith(".so")) actualName = actualName + ".so";

  const m = Process.findModuleByName(actualName);
  if (!m) return;

  log.info(TAG, "Scanning memory of " + actualName + " for suspicious strings...");

  // Per-iteration `const pattern` binding so each onMatch closure captures its
  // own pattern rather than the last one in the list.
  for (const pattern of SCAN_PATTERNS) {
    Memory.scan(m.base, m.size, pattern.hex, {
      onMatch: function (address: NativePointer, size: number) {
        log.detect(TAG, "Found embedded string: [" + pattern.name + "] at " + address);
      },
      onError: function (reason: string) {},
      onComplete: function () {},
    });
  }
}

const mod: DecloakerModule = {
  id: "java-native-loaders",
  tag: TAG,
  description:
    "Detects Java-side native library loading (System/Runtime load & loadLibrary) and scans freshly loaded libs for embedded emulator/tooling strings",
  enabledByDefault: false,
  requires: "java",
  install() {
    // withJava is a silent no-op when Java is unavailable, matching the legacy
    // `if (!Java.available) return;` guard at the top of hookJavaNativeLoaders.
    withJava(() => {
      const System = Java.use("java.lang.System");
      const Runtime = Java.use("java.lang.Runtime");
      const Log = Java.use("android.util.Log");
      const Exception = Java.use("java.lang.Exception");
      // Shadows the ambient frida-gum `Thread` on purpose: inside this callback
      // we want the java.lang.Thread wrapper for the race-condition sleep.
      const Thread = Java.use("java.lang.Thread");

      // Nested (not module-scope) because it closes over the Log/Exception
      // Java.use() wrappers, which only exist inside this Java.perform callback.
      function logNativeLoad(methodName: string, libName: string): void {
        // Java stack trace, not a native backtrace: grab it via a throwaway
        // Exception and Log's formatter. Skip the top frame (this hook) and cap
        // depth for readability - same slice(1, 8) as legacy.
        const instance = Exception.$new("NativeLoadTrace");
        const stack: string[] = Log.getStackTraceString(instance).split("\n");
        const cleanStack = stack.slice(1, 8).join("\n    ");
        log.detect(TAG, "Dynamic Library Load Detected: " + methodName, [["Target", libName]], cleanStack);
      }

      // Classic `function` expressions (never arrows): frida-java-bridge binds
      // `this` per-call to the invoking wrapper so `this.load(...)` /
      // `this.loadLibrary(...)` chain to the real method. Params are annotated
      // `: any` to satisfy noImplicitAny.
      System.load.overload("java.lang.String").implementation = function (this: any, filename: any) {
        logNativeLoad("System.load", filename);
        return this.load(filename);
      };

      System.loadLibrary.overload("java.lang.String").implementation = function (this: any, libname: any) {
        logNativeLoad("System.loadLibrary", libname);

        // FIX: the script kept crashing with monochrome and webview related
        // errors. Let those system libraries fail naturally without sleeping.
        if (libname.indexOf("monochrome") !== -1 || libname.indexOf("webview") !== -1) {
          return this.loadLibrary(libname);
        }

        try {
          const result = this.loadLibrary(libname);

          // Scan the library immediately after it successfully loads (skipped
          // for framework libs - see isSystemLib, which repairs the legacy
          // undefined reference).
          if (!isSystemLib(libname)) scanModuleMemory(libname);

          return result;
        } catch {
          log.detect(TAG, "UnsatisfiedLinkError. Suspected extraction race condition.", [
            ["Action", "Sleeping for 3 seconds to allow dropping to finish..."],
          ]);
          Thread.sleep(3000); // 3 second stall

          const result = this.loadLibrary(libname);
          log.info(TAG, "Retry successful!");

          // Scan the library if the retry was successful.
          scanModuleMemory(libname);

          return result;
        }
      };

      Runtime.load.overload("java.lang.String").implementation = function (this: any, filename: any) {
        logNativeLoad("Runtime.load", filename);
        return this.load(filename);
      };

      try {
        Runtime.loadLibrary.overload("java.lang.String").implementation = function (this: any, libname: any) {
          logNativeLoad("Runtime.loadLibrary", libname);
          try {
            return this.loadLibrary(libname);
          } catch {
            log.detect(TAG, "UnsatisfiedLinkError. Suspected extraction race condition.", [
              ["Action", "Sleeping for 3 seconds to allow dropping to finish..."],
            ]);
            Thread.sleep(3000);
            const result = this.loadLibrary(libname);
            log.info(TAG, "Retry successful!");
            return result;
          }
        };
      } catch (e: any) {
        log.warn(TAG, "Runtime.loadLibrary hook unavailable: " + e.message);
      }

      log.setup(
        TAG,
        "Hooked Java Native Loaders (System.load, System.loadLibrary) with Race Condition Fix"
      );
    });
  },
};

export default mod;
