// Ported from legacy decloaker.js hookJNIEnv (lines 1149-1223), including its
// nested hookJniMethod helper.
//
// Hooks the JNIEnv function table directly (rather than named native exports)
// so JNI method/string lookups are caught even when the JVM resolves them via
// the vtable instead of a symbol - this is what makes the hook "universal"
// across ART implementations.

import type { DecloakerModule, IC } from "../types";
import { Java, withJava } from "../core/java";
import { log } from "../core/logger";
import { isTargetCaller, getNativeBacktrace } from "../core/backtrace";
import { readStrSafe } from "../core/memory";
import { scan } from "../filters/matcher";

const TAG = "JNIEnv table";

type JniHookKind = "method" | "newstring" | "getstring";

// Hoisted out of install() - it only needs its explicit args (no closure
// over install()'s locals), so it lives at module scope like the rest of
// this file's helpers.
function hookJniMethod(ptrAddress: NativePointer, name: string, type: JniHookKind): void {
  if (!ptrAddress || ptrAddress.isNull()) {
    log.warn(TAG, "Cannot resolve pointer for JNI " + name);
    return;
  }

  try {
    Interceptor.attach(ptrAddress, {
      onEnter: function (this: IC, args) {
        this.retAddr = this.returnAddress;
        this.myCtx = this.context;
        if (!isTargetCaller(this.retAddr)) {
          this.skip = true;
          return;
        }
        this.skip = false;

        // Capture the context into a local; inside the trace closures below
        // `this` is NOT the Interceptor context (scan calls them bare).
        const ctx = this.myCtx;
        if (type === "method") {
          const nameStr = readStrSafe(args[2]);
          const sigStr = readStrSafe(args[3]);
          scan("JNI " + name, nameStr + sigStr, () => getNativeBacktrace(ctx));
        } else if (type === "newstring") {
          const str = readStrSafe(args[1]);
          scan("JNI " + name, str, () => getNativeBacktrace(ctx));
        }
      },
      onLeave: function (this: IC, retval) {
        if (this.skip || retval.isNull()) return;
        if (type === "getstring") {
          const str = readStrSafe(retval);
          const ctx = this.myCtx;
          scan("JNI " + name, str, () => getNativeBacktrace(ctx));
        }
      },
    });
  } catch (e: any) {
    log.warn(TAG, "Failed hooking JNI " + name + ": " + e.message);
  }
}

const mod: DecloakerModule = {
  id: "jni-env",
  tag: TAG,
  description: "Hooks the JNIEnv vtable (GetMethodID/GetStaticMethodID/NewStringUTF/GetStringUTFChars) for target strings",
  enabledByDefault: true,
  requires: "java",
  install() {
    withJava(function () {
      try {
        const env = Java.vm.getEnv();
        if (!env || !env.handle) {
          log.warn(TAG, "JNIEnv handle not available.");
          return;
        }

        // Use the instance method NativePointer.readPointer(); the static Memory.readPointer()
        // was REMOVED in Frida 17, and would throw here (silently disabling every JNIEnv hook).
        const envPtr = ptr(env.handle);
        const vtable = envPtr.readPointer();
        const pSize = Process.pointerSize;

        // Standard JNIEnv function-table indices (jni.h): GetMethodID=33,
        // GetStaticMethodID=113, NewStringUTF=167, GetStringUTFChars=169.
        const getMethodIdPtr = vtable.add(33 * pSize).readPointer();
        const getStaticMethodIdPtr = vtable.add(113 * pSize).readPointer();
        const newStringUtfPtr = vtable.add(167 * pSize).readPointer();
        const getStringUtfCharsPtr = vtable.add(169 * pSize).readPointer();

        hookJniMethod(getMethodIdPtr, "GetMethodID", "method");
        hookJniMethod(getStaticMethodIdPtr, "GetStaticMethodID", "method");
        hookJniMethod(newStringUtfPtr, "NewStringUTF", "newstring");
        hookJniMethod(getStringUtfCharsPtr, "GetStringUTFChars", "getstring");

        log.setup(TAG, "Hooked core JNIEnv APIs successfully.");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook JNIEnv vtable: " + e.message);
      }
    });
  },
};

export default mod;
