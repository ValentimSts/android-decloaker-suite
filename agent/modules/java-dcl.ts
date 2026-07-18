// Ported from legacy decloaker.js hookJavaDCL (lines 592-644).
//
// Flags dynamic class loading (DexClassLoader / PathClassLoader /
// InMemoryDexClassLoader) - a common technique for loading a second-stage
// payload dex/jar at runtime to dodge static analysis of the APK.

import { Java } from "../core/java";
import { log } from "../core/logger";
import type { DecloakerModule } from "../types";

const TAG = "DCL";

const mod: DecloakerModule = {
  id: "java-dcl",
  tag: TAG,
  description: "Detects dynamic class loading via DexClassLoader/PathClassLoader/InMemoryDexClassLoader",
  enabledByDefault: true,
  requires: "java",
  install() {
    // Belt-and-suspenders: the dispatcher already gates this module on
    // Java.available via `requires: "java"`, but the legacy script checked
    // here too and we keep behavior identical.
    if (!Java.available) {
      log.warn(TAG, "Java is not available. Skipping DCL hooks.");
      return;
    }

    Java.perform(function () {
      const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
      const PathClassLoader = Java.use("dalvik.system.PathClassLoader");
      const InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
      const Log = Java.use("android.util.Log");
      const Exception = Java.use("java.lang.Exception");

      // Nested (not module-scope) because it closes over the Log/Exception
      // Java.use() wrappers above, which only exist inside this
      // Java.perform() callback.
      function logDCL(
        type: string,
        dexPath: string | null,
        optimizedDirectory: string | null,
        librarySearchPath: string | null
      ) {
        const fields: [string, string][] = [];
        if (dexPath) fields.push(["Target", dexPath]);
        if (optimizedDirectory) fields.push(["Opt Dir", optimizedDirectory]);
        if (librarySearchPath) fields.push(["Lib Path", librarySearchPath]);

        // Java stack trace, not a native backtrace - grab it via a throwaway
        // Exception instance and Log's formatter, same as legacy. Skip the
        // top frame (this hook itself) and cap depth for readability.
        const instance = Exception.$new("DCLStackTrace");
        const stack: string[] = Log.getStackTraceString(instance).split("\n");
        const cleanStack = stack.slice(1, 8).join("\n    ");

        log.detect(TAG, "Suspicious Dynamic Class Loading Detected: " + type, fields, cleanStack);
      }

      // Classic `function` expressions below (never arrows): each is assigned
      // to a Java .implementation property, and frida-java-bridge binds `this`
      // per-call to the instantiated Wrapper so `this.$init(...)` chains to
      // the real constructor - an arrow would capture the wrong `this`.
      DexClassLoader.$init.implementation = function (
        dexPath: any,
        optimizedDirectory: any,
        librarySearchPath: any,
        parent: any
      ) {
        logDCL("DexClassLoader", dexPath, optimizedDirectory, librarySearchPath);
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
      };

      PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function (
        dexPath: any,
        parent: any
      ) {
        logDCL("PathClassLoader", dexPath, null, null);
        return this.$init(dexPath, parent);
      };
      PathClassLoader.$init.overload(
        "java.lang.String",
        "java.lang.String",
        "java.lang.ClassLoader"
      ).implementation = function (dexPath: any, librarySearchPath: any, parent: any) {
        logDCL("PathClassLoader", dexPath, null, librarySearchPath);
        return this.$init(dexPath, librarySearchPath, parent);
      };

      // InMemoryDexClassLoader was added in API 26 - guard so a missing
      // class on older devices doesn't abort the rest of module install.
      try {
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation =
          function (dexBuffer: any, parent: any) {
            logDCL("InMemoryDexClassLoader", "Memory Buffer (Capacity: " + dexBuffer.capacity() + ")", null, null);
            return this.$init(dexBuffer, parent);
          };
        InMemoryDexClassLoader.$init.overload("[Ljava.nio.ByteBuffer;", "java.lang.ClassLoader").implementation =
          function (dexBuffers: any, parent: any) {
            logDCL(
              "InMemoryDexClassLoader",
              "Memory Buffer Array (Length: " + dexBuffers.length + ")",
              null,
              null
            );
            return this.$init(dexBuffers, parent);
          };
      } catch (e: any) {
        log.warn(TAG, "InMemoryDexClassLoader hook unavailable: " + e.message);
      }

      log.setup(TAG, "Hooked Java DCL APIs (DexClassLoader, PathClassLoader, InMemoryDexClassLoader)");
    });
  },
};

export default mod;
