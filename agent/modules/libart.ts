// Ported from legacy decloaker.js hookLibart (lines 1092-1148).
//
// Hooks libart.so's JNI RegisterNatives and FindClass exports directly (as
// opposed to hooking through a live JNIEnv struct), so it catches native
// binding activity even before/around any JNIEnv-based hooks are set up.

import { log } from "../core/logger";
import { readStrSafe } from "../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../core/backtrace";
import { scan } from "../filters/matcher";
import type { DecloakerModule, IC } from "../types";

const TAG = "JNI";

const mod: DecloakerModule = {
  id: "libart",
  tag: TAG,
  description: "Hooks libart.so JNI RegisterNatives/FindClass exports directly",
  enabledByDefault: true,
  install() {
    // libart.so may not be resolvable (e.g. some hardened runtimes) - bail
    // quietly, matching the legacy silent-return-on-failure behavior.
    let exportsList: ModuleExportDetails[] = [];
    try {
      exportsList = Process.getModuleByName("libart.so").enumerateExports();
    } catch (e) {
      return;
    }

    // Only the FIRST matching export of each kind gets hooked - libart.so
    // commonly exposes multiple JNI trampoline aliases for the same entry
    // point, and re-hooking all of them would just duplicate every alert.
    let hookedFindClass = false;
    let hookedRegisterNatives = false;

    for (let i = 0; i < exportsList.length; i++) {
      const name = exportsList[i].name;

      if (
        !hookedRegisterNatives &&
        name.indexOf("RegisterNatives") !== -1 &&
        name.indexOf("JNI") !== -1 &&
        name.indexOf("CheckJNI") === -1
      ) {
        try {
          Interceptor.attach(exportsList[i].address, {
            onEnter: function (this: IC, args) {
              if (!isTargetCaller(this.returnAddress)) return;
              const methodsPtr = args[2];
              const methodCount = args[3].toInt32();

              // JNINativeMethod is { name, signature, fnPtr } - three
              // pointer-sized fields per entry, hence the *3 stride. Collect
              // each binding as a field so the whole batch surfaces as one
              // alert (matching the legacy header + per-method print block).
              const fields: [string, string][] = [];
              for (let j = 0; j < methodCount; j++) {
                const offset = j * Process.pointerSize * 3;
                const namePtr = methodsPtr.add(offset).readPointer();
                const sigPtr = methodsPtr.add(offset + Process.pointerSize).readPointer();
                const fnPtr = methodsPtr.add(offset + Process.pointerSize * 2).readPointer();

                const mName = readStrSafe(namePtr);
                const sig = readStrSafe(sigPtr);
                const foundMod = Process.findModuleByAddress(fnPtr);
                const modName = foundMod ? foundMod.name : "Unknown Module";

                fields.push([mName + sig, fnPtr + " (" + modName + ")"]);
                scan("RegisterNatives Name", mName);
              }

              log.detect(
                TAG,
                "RegisterNatives Triggered! Binding " + methodCount + " methods.",
                fields.length ? fields : undefined
              );
            },
          });
          hookedRegisterNatives = true;
          log.setup(TAG, "Hooked JNI Runtime: RegisterNatives");
        } catch (e: any) {
          log.warn(TAG, "RegisterNatives hook failed: " + e.message);
        }
      }

      if (
        !hookedFindClass &&
        name.indexOf("JNI") !== -1 &&
        name.indexOf("FindClass") !== -1 &&
        name.indexOf("CheckJNI") === -1
      ) {
        try {
          Interceptor.attach(exportsList[i].address, {
            onEnter: function (this: IC, args) {
              if (!isTargetCaller(this.returnAddress)) return;
              // Copy this.context into a local so the trace thunk below
              // closes over that value instead of `this` - scan() invokes
              // the thunk bare, with no `this` binding at all.
              const ctx = this.context;
              scan("JNI FindClass", readStrSafe(args[1]), () => getNativeBacktrace(ctx));
            },
          });
          hookedFindClass = true;
        } catch (e: any) {
          log.warn(TAG, "FindClass hook failed: " + e.message);
        }
      }
    }
  },
};

export default mod;
