// Ported from legacy decloaker.js hookReflection (lines 3784-3989), including its
// nested reflectBacktrace/logReflect/fieldName helpers.
//
// Malware hides calls behind java.lang.reflect to defeat static analysis and simple Java
// hooks: Method.invoke / Class.forName / ClassLoader.loadClass / Constructor.newInstance /
// Field access. Detection-only - only the reflection ENTRY POINTS below are instrumented
// (never every Method/Class API) to avoid recursing through our own hook machinery and to
// keep overhead bounded.
//
// GATING: Method.invoke, ClassLoader.loadClass and Field.get/set are extremely hot in a
// normal Android app (the framework itself drives them constantly). scan() is the gate: the
// noisy detect header + Java backtrace (logReflect) fires ONLY when the class/method/field
// name actually matches the evasion lexicon, so these hooks never flood the console or stall
// the app on a non-match.

import { Java, withJava } from "../core/java";
import { log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { scan } from "../filters/matcher";
import type { DecloakerModule } from "../types";

const TAG = "REFLECTION";

const mod: DecloakerModule = {
  id: "reflection",
  tag: TAG,
  description:
    "Detects reflection-based evasion via Method.invoke, Class.forName, ClassLoader.loadClass, Constructor.newInstance, Field.setAccessible",
  enabledByDefault: true,
  requires: "java",
  install() {
    // withJava no-ops when Java is unavailable; the dispatcher also gates this
    // module on `requires: "java"`, so the legacy explicit Java.available guard
    // is unreachable here and its warning is dropped.
    withJava(() => {
      // Resolve Log/Exception independently so one missing class does not disable the other.
      let Log: Java.Wrapper | null = null;
      let Exception: Java.Wrapper | null = null;
      try {
        Log = Java.use("android.util.Log");
      } catch (e: any) {
        log.warn(TAG, "Reflection: could not resolve android.util.Log for backtraces: " + e.message);
      }
      try {
        Exception = Java.use("java.lang.Exception");
      } catch (e: any) {
        log.warn(TAG, "Reflection: could not resolve java.lang.Exception for backtraces: " + e.message);
      }

      // Short Java backtrace, matching the file's logDCL/logNativeLoad convention. Wrapped so a
      // failure to build the stack never breaks the underlying reflection call.
      function reflectBacktrace(): string {
        if (!Log || !Exception) return "[Java Backtrace unavailable]";
        try {
          const instance = Exception.$new("ReflectionTrace");
          const stack: string[] = Log.getStackTraceString(instance).split("\n");
          return stack.slice(1, 8).join("\n    ");
        } catch (e) {
          return "[Java Backtrace unavailable]";
        }
      }

      // Only ever called AFTER scan() has confirmed a lexicon match, so building the Java
      // stack here is bounded to genuine hits.
      function logReflect(headline: string, detail: string | null): void {
        const bt = reflectBacktrace();

        // Legacy's OWN dedup layer, separate from scan()'s: keyed on this exact
        // headline+detail+backtrace triple, so the same reflection call from the
        // same stack never floods the console twice.
        const sig = "reflect|" + headline + "|" + detail + "|" + bt;
        if (hasSeen(sig)) return;
        markSeen(sig);

        const fields: [string, string][] = [];
        if (detail) fields.push(["Detail", detail]);
        log.detect(TAG, headline, fields.length ? fields : undefined, bt);
      }

      // --- java.lang.reflect.Method.invoke ---
      try {
        const Method = Java.use("java.lang.reflect.Method");
        Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function (
          this: any,
          obj: any,
          argArr: any
        ) {
          try {
            // `this` is the Java Method wrapper here (valid inside a Frida implementation),
            // NOT an Interceptor context - getName()/getDeclaringClass() are the correct API.
            let declClass = "";
            try {
              declClass = this.getDeclaringClass().getName();
            } catch (e) {}
            let mName = "";
            try {
              mName = this.getName();
            } catch (e) {}
            const fqmn = declClass + "." + mName;
            // fqmn already contains declClass, so a single scan() covers both.
            if (scan("Reflection Method.invoke", fqmn)) {
              logReflect("Method.invoke -> " + fqmn, null);
            }
          } catch (e) {}
          return this.invoke(obj, argArr);
        };
        log.setup(TAG, "Hooked reflection: Method.invoke");
      } catch (e: any) {
        log.warn(TAG, "Could not hook Method.invoke: " + e.message);
      }

      // --- java.lang.Class.forName ---
      try {
        const Clazz = Java.use("java.lang.Class");
        try {
          Clazz.forName.overload("java.lang.String").implementation = function (this: any, name: any) {
            if (scan("Reflection Class.forName", "" + name)) {
              logReflect("Class.forName", "" + name);
            }
            return this.forName(name);
          };
        } catch (e: any) {
          log.warn(TAG, "Class.forName(String) overload unavailable: " + e.message);
        }
        try {
          Clazz.forName.overload("java.lang.String", "boolean", "java.lang.ClassLoader").implementation = function (
            this: any,
            name: any,
            init: any,
            loader: any
          ) {
            if (scan("Reflection Class.forName", "" + name)) {
              logReflect("Class.forName", "" + name);
            }
            return this.forName(name, init, loader);
          };
        } catch (e: any) {
          log.warn(TAG, "Class.forName(String,boolean,ClassLoader) overload unavailable: " + e.message);
        }
        // NOTE: the (Class, String) caller-context overload from the authored version was
        // dropped - it is not part of Android's libcore java.lang.Class API, so it never
        // resolves (and this.forName(caller, name) would be an invalid dispatch anyway).
        log.setup(TAG, "Hooked reflection: Class.forName");
      } catch (e: any) {
        log.warn(TAG, "Could not hook Class.forName: " + e.message);
      }

      // --- java.lang.ClassLoader.loadClass ---
      try {
        const CL = Java.use("java.lang.ClassLoader");
        try {
          CL.loadClass.overload("java.lang.String").implementation = function (this: any, name: any) {
            if (scan("Reflection ClassLoader.loadClass", "" + name)) {
              logReflect("ClassLoader.loadClass", "" + name);
            }
            return this.loadClass(name);
          };
        } catch (e: any) {
          log.warn(TAG, "ClassLoader.loadClass(String) overload unavailable: " + e.message);
        }
        // Protected (String, boolean) form - Frida can still bind it; wrap defensively.
        try {
          CL.loadClass.overload("java.lang.String", "boolean").implementation = function (
            this: any,
            name: any,
            resolve: any
          ) {
            if (scan("Reflection ClassLoader.loadClass", "" + name)) {
              logReflect("ClassLoader.loadClass", "" + name);
            }
            return this.loadClass(name, resolve);
          };
        } catch (e) {}
        log.setup(TAG, "Hooked reflection: ClassLoader.loadClass");
      } catch (e: any) {
        log.warn(TAG, "Could not hook ClassLoader.loadClass: " + e.message);
      }

      // --- java.lang.reflect.Constructor.newInstance ---
      try {
        const Constructor = Java.use("java.lang.reflect.Constructor");
        // newInstance(Object...) lowers to a single [Ljava.lang.Object; overload.
        Constructor.newInstance.overload("[Ljava.lang.Object;").implementation = function (this: any, argArr: any) {
          try {
            let declClass = "";
            try {
              declClass = this.getDeclaringClass().getName();
            } catch (e) {}
            if (scan("Reflection Constructor.newInstance", declClass)) {
              logReflect("Constructor.newInstance -> " + declClass, null);
            }
          } catch (e) {}
          return this.newInstance(argArr);
        };
        log.setup(TAG, "Hooked reflection: Constructor.newInstance");
      } catch (e: any) {
        log.warn(TAG, "Could not hook Constructor.newInstance: " + e.message);
      }

      // --- java.lang.reflect.Field get/set/setAccessible ---
      try {
        const Field = Java.use("java.lang.reflect.Field");

        function fieldName(self: Java.Wrapper): string {
          let declClass = "";
          try {
            declClass = self.getDeclaringClass().getName();
          } catch (e) {}
          let fName = "";
          try {
            fName = self.getName();
          } catch (e) {}
          return declClass + "." + fName;
        }

        // NOTE: Field.get / Field.set are deliberately NOT hooked. They are among the hottest
        // Java paths (Gson/Jackson/Kotlin serialization walk every field), and building the
        // declaring-class + field name on every call - two JNI crossings + a regex - adds real
        // overhead to a benign framework hot path for little signal. setAccessible (below) is
        // the actual evasion tell (forcing access to private/@hide members) and is far less hot.

        // setAccessible: single-Field instance form. The bulk AccessibleObject.setAccessible
        // static form is intentionally left alone to avoid noisy/broad framework matches.
        try {
          Field.setAccessible.overload("boolean").implementation = function (this: any, flag: any) {
            const fqfn = fieldName(this);
            if (scan("Reflection Field.setAccessible", fqfn)) {
              logReflect("Field.setAccessible(" + flag + ") -> " + fqfn, null);
            }
            return this.setAccessible(flag);
          };
        } catch (e: any) {
          log.warn(TAG, "Field.setAccessible overload unavailable: " + e.message);
        }

        log.setup(TAG, "Hooked reflection: Field.setAccessible");
      } catch (e: any) {
        log.warn(TAG, "Could not hook Field APIs: " + e.message);
      }

      log.setup(TAG, "Hooked Java reflection entry points");
    });
  },
};

export default mod;
