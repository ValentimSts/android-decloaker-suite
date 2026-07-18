// Ported from legacy decloaker.js hookJNIEnvExtended (lines 1474-1779), plus its
// module-private jniRememberMethod/jniLookupMethod helpers and the JNI_METHOD_MAP/
// JNI_REGION_READ_CAP state.
//
// Extends the core JNIEnv coverage in the core "jni-env" module (which already owns
// slots 33/113/167/169). Every slot below was verified against the canonical
// JNINativeInterface layout in jni.h: 4 reserved pointers precede GetVersion=4, and
// the anchors this file already trusts line up exactly (GetMethodID=33,
// GetStaticMethodID=113, NewStringUTF=167, GetStringUTFChars=169).
// Confirmed indices: DefineClass=5, ThrowNew=14, ExceptionOccurred=15, GetMethodID=33,
// CallObjectMethod=34, CallBooleanMethodA=39, CallVoidMethod=61, GetFieldID=94,
// GetStaticMethodID=113, CallStaticObjectMethod=114, CallStaticBooleanMethodA=119,
// CallStaticVoidMethod=141, GetStaticFieldID=144, GetByteArrayElements=184,
// GetByteArrayRegion=200, GetStringRegion=220, GetStringUTFRegion=221.
//
// NOTE on the "Boolean" representatives: the Boolean slots hooked here are 39 and 119,
// which are CallBooleanMethodA / CallStaticBooleanMethodA (the jvalue-array form). The
// plain varargs CallBooleanMethod is 37 and CallStaticBooleanMethod is 117 - we
// intentionally hook the A form at 39/119 per the assignment. Object (34/114) and Void
// (61/141) are the base varargs forms. For every Call<Type>Method / CallStatic<Type>Method
// entry args[0]=JNIEnv, args[1]=jobject/jclass, args[2]=jmethodID; we correlate args[2] to
// the name+sig map built from GetMethodID / GetStaticMethodID returns (they return the
// jmethodID as the retval).

import { log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { readStrSafe, payloadMagic, dumpBuffer } from "../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../core/backtrace";
import { Java, withJava } from "../core/java";
import { scan } from "../filters/matcher";
import type { IC, DecloakerModule } from "../types";

const TAG = "JNI";

// Bounded jmethodID -> "name+sig" correlation map, populated by GetMethodID/
// GetStaticMethodID onLeave and read by the Call*Method hooks. Bounded like the
// dedup store so a long-running sample that resolves thousands of methods cannot
// grow it without limit.
const JNI_METHOD_MAP: Record<string, string> = {};
let JNI_METHOD_MAP_SIZE = 0;
const JNI_METHOD_MAP_CAP = 4000;

// Upper bound on how many code units we will read out of a GetString*Region
// destination buffer. jsize len is attacker-influenced; a bogus/huge value must not
// drive a multi-MB read.
const JNI_REGION_READ_CAP = 8192;

function jniRememberMethod(idPtr: NativePointer | null | undefined, name: string, sig: string): void {
  try {
    if (!idPtr || idPtr.isNull()) return;
    const key = idPtr.toString();
    if (Object.prototype.hasOwnProperty.call(JNI_METHOD_MAP, key)) return;
    // Stop growing once full rather than wiping+refilling: a churn-heavy app would
    // otherwise repeatedly clear the map and re-read/re-insert on every GetMethodID (a
    // hot path). A stale full map is fine - it only supplies best-effort name labels
    // for the Call* hooks.
    if (JNI_METHOD_MAP_SIZE >= JNI_METHOD_MAP_CAP) return;
    JNI_METHOD_MAP[key] = (name || "?") + (sig || "");
    JNI_METHOD_MAP_SIZE++;
  } catch (e) {}
}

function jniLookupMethod(idPtr: NativePointer | null | undefined): string | null {
  try {
    if (!idPtr || idPtr.isNull()) return null;
    return JNI_METHOD_MAP[idPtr.toString()] || null;
  } catch (e) {
    return null;
  }
}

const mod: DecloakerModule = {
  id: "jni-extended",
  tag: TAG,
  description:
    "Extended JNIEnv vtable hooks: Call*Method name correlation, region/byte-array reads, DefineClass, ThrowNew",
  enabledByDefault: true,
  requires: "java",
  install() {
    if (!Java.available) {
      log.warn(TAG, "Java is not available. Skipping extended JNIEnv hooks.");
      return;
    }

    withJava(() => {
      try {
        const env = Java.vm.getEnv();
        if (!env || !env.handle) {
          log.warn(TAG, "JNIEnv handle not available (extended).");
          return;
        }

        // Resolve the vtable exactly like the core "jni-env" module: envPtr ->
        // readPointer() -> function table. NativePointer.readPointer() (Frida 16/17);
        // the static Memory.readPointer() was removed.
        const envPtr = ptr(env.handle);
        const vtable = envPtr.readPointer();
        const pSize = Process.pointerSize;

        // Guarded slot read: returns null (never throws) if the slot pointer is null so
        // callers can skip that hook rather than tearing down the whole install.
        function slot(index: number): NativePointer | null {
          try {
            const p = vtable.add(index * pSize).readPointer();
            if (!p || p.isNull()) return null;
            return p;
          } catch (e) {
            return null;
          }
        }

        // Generic attach helper: skips a null slot and wraps Interceptor.attach in
        // try/catch so one bad slot cannot abort the rest.
        function attachSlot(index: number, name: string, callbacks: InvocationListenerCallbacks): void {
          const p = slot(index);
          if (!p) {
            log.warn(TAG, "JNIEnv slot " + index + " (" + name + ") null - skipped.");
            return;
          }
          try {
            Interceptor.attach(p, callbacks);
            log.setup(TAG, "Hooked JNIEnv " + name + " (slot " + index + ")");
          } catch (e: any) {
            log.warn(TAG, "Failed hooking JNIEnv " + name + " (slot " + index + "): " + e.message);
          }
        }

        // ---- GetStringUTFRegion (221) / GetStringRegion (220) ----
        // jint GetStringUTFRegion(env, jstring, jsize start, jsize len, char* buf)
        // -> args[0]=env, args[1]=jstring, args[2]=start, args[3]=len, args[4]=dest buffer.
        // The dest buffer is only populated AFTER the call: capture dest+len onEnter,
        // read+scan onLeave. Gated by isTargetCaller so we only inspect calls from target
        // modules, and the read length is clamped to JNI_REGION_READ_CAP so a bogus len
        // cannot drive a huge read.
        attachSlot(221, "GetStringUTFRegion", {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.dest = args[4];
            const n = args[3].toInt32();
            this.len = n > JNI_REGION_READ_CAP ? JNI_REGION_READ_CAP : n;
            this.myCtx = this.context;
          },
          onLeave: function (this: IC) {
            if (this.skip || !this.dest || this.dest.isNull() || this.len <= 0) return;
            // GetStringUTFRegion writes modified-UTF-8; read at most len bytes (safe upper
            // bound). args[3] is a CHARACTER count but readUtf8String wants a BYTE count;
            // modified UTF-8 is up to 3 bytes/char (BMP), so read a 3x window (capped) to
            // avoid slicing a multi-byte sequence mid-character.
            const s = readStrSafe(this.dest, Math.min(this.len * 3, JNI_REGION_READ_CAP));
            if (!s) return;
            const ctx = this.myCtx;
            scan("JNI GetStringUTFRegion", s, () => getNativeBacktrace(ctx));
          },
        });
        // GetStringRegion writes UTF-16 (jchar*) into dest; decode with readUtf16String(len).
        attachSlot(220, "GetStringRegion", {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.dest = args[4];
            const n = args[3].toInt32();
            this.len = n > JNI_REGION_READ_CAP ? JNI_REGION_READ_CAP : n;
            this.myCtx = this.context;
          },
          onLeave: function (this: IC) {
            if (this.skip || !this.dest || this.dest.isNull() || this.len <= 0) return;
            let s = "";
            try {
              s = this.dest.readUtf16String(this.len) || "";
            } catch (e) {
              s = "";
            }
            if (!s) return;
            const ctx = this.myCtx;
            scan("JNI GetStringRegion", s, () => getNativeBacktrace(ctx));
          },
        });

        // ---- GetByteArrayElements (184) / GetByteArrayRegion (200) ----
        // These surface decrypted DEX/ELF/ZIP payloads that never touch libc file I/O.
        // GetByteArrayElements(env, jbyteArray, jboolean* isCopy) -> retval = jbyte* buffer.
        // We do not know the array length here, so only act when the first bytes match a
        // known payload magic (payloadMagic reads just 4 bytes, fault-guarded) and hand a
        // fixed preview window to dumpBuffer (which caps and fault-guards its own reads).
        // Gated by caller and by magic so benign byte arrays (every String.getBytes(), etc.)
        // never flood.
        const BA_PREVIEW = 4096;
        attachSlot(184, "GetByteArrayElements", {
          onEnter: function (this: IC) {
            this.skip = !isTargetCaller(this.returnAddress);
          },
          onLeave: function (this: IC, retval) {
            if (this.skip || !retval || retval.isNull()) return;
            try {
              const magic = payloadMagic(retval);
              if (magic) {
                dumpBuffer("JNI_GetByteArrayElements_" + magic, retval, BA_PREVIEW);
              }
            } catch (e) {}
          },
        });
        // GetByteArrayRegion(env, jbyteArray, jsize start, jsize len, jbyte* buf) copies into
        // args[4]; length is known (args[3]) and the buffer is filled AFTER the call.
        attachSlot(200, "GetByteArrayRegion", {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.dest = args[4];
            this.len = args[3].toInt32();
          },
          onLeave: function (this: IC) {
            if (this.skip || !this.dest || this.dest.isNull() || this.len <= 0) return;
            try {
              const magic = payloadMagic(this.dest);
              if (magic) {
                dumpBuffer("JNI_GetByteArrayRegion_" + magic, this.dest, this.len);
              }
            } catch (e) {}
          },
        });

        // ---- GetMethodID (33) / GetStaticMethodID (113): map builders ----
        // These are ALSO hooked in the core "jni-env" module for detection; here we attach
        // an INDEPENDENT listener (Interceptor allows multiple listeners per address) that
        // ONLY records jmethodID -> name+sig into JNI_METHOD_MAP (no detection, no spoof),
        // so the Call*Method hooks below can resolve the method being invoked. Deliberately
        // NOT gated by isTargetCaller: the map must be complete regardless of resolver, or
        // Call* lookups miss. GetMethodID(env, clazz, char* name, char* sig) -> retval =
        // jmethodID.
        function attachMethodIdMapper(index: number, label: string): void {
          attachSlot(index, label + " (map)", {
            onEnter: function (this: IC, args) {
              this.mName = readStrSafe(args[2]);
              this.mSig = readStrSafe(args[3]);
            },
            onLeave: function (this: IC, retval) {
              jniRememberMethod(retval, this.mName, this.mSig);
            },
          });
        }
        attachMethodIdMapper(33, "GetMethodID");
        attachMethodIdMapper(113, "GetStaticMethodID");

        // ---- Call<Type>Method + CallStatic<Type>Method representatives ----
        // Representative slots: Object=34/114, Void=61/141, Boolean=39/119 (39/119 are the
        // CallBooleanMethodA / CallStaticBooleanMethodA jvalue-array forms). args[2] =
        // jmethodID; resolve it against JNI_METHOD_MAP and run the resolved "name+sig"
        // through scan() so evasive reflective-style native dispatch is caught. Gated by
        // isTargetCaller AND by a successful map lookup, so these very hot slots stay quiet
        // unless there is real signal.
        function attachCallHook(index: number, label: string): void {
          attachSlot(index, label, {
            onEnter: function (this: IC, args) {
              if (!isTargetCaller(this.returnAddress)) return;
              const resolved = jniLookupMethod(args[2]);
              if (!resolved) return; // no signal without a known name+sig
              const ctx = this.context;
              scan("JNI " + label, resolved, () => getNativeBacktrace(ctx));
            },
          });
        }
        attachCallHook(34, "CallObjectMethod");
        attachCallHook(114, "CallStaticObjectMethod");
        attachCallHook(61, "CallVoidMethod");
        attachCallHook(141, "CallStaticVoidMethod");
        attachCallHook(39, "CallBooleanMethodA");
        attachCallHook(119, "CallStaticBooleanMethodA");

        // ---- GetFieldID (94) / GetStaticFieldID (144): name + sig ----
        // GetFieldID(env, clazz, char* name, char* sig). Detection-only on name+sig.
        function attachFieldId(index: number, label: string): void {
          attachSlot(index, label, {
            onEnter: function (this: IC, args) {
              if (!isTargetCaller(this.returnAddress)) return;
              const fName = readStrSafe(args[2]);
              const fSig = readStrSafe(args[3]);
              if (!fName && !fSig) return;
              const ctx = this.context;
              scan("JNI " + label, fName + fSig, () => getNativeBacktrace(ctx));
            },
          });
        }
        attachFieldId(94, "GetFieldID");
        attachFieldId(144, "GetStaticFieldID");

        // ---- DefineClass (5) ----
        // DefineClass(env, char* name, jobject loader, jbyte* buf, jsize len) - args[1]=name,
        // args[3]=class-bytes buffer, args[4]=len. This is in-memory class injection: dump
        // the buffer (dumpBuffer honours config.dumpPayloads) and scan the class name.
        attachSlot(5, "DefineClass", {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const name = readStrSafe(args[1]);
            const buf = args[3];
            let len = 0;
            try {
              len = args[4].toInt32();
            } catch (e) {
              len = 0;
            }
            const ctx = this.context;
            if (name) {
              scan("JNI DefineClass", name, () => getNativeBacktrace(ctx));
            }
            if (buf && !buf.isNull() && len > 0) {
              try {
                dumpBuffer("JNI_DefineClass_" + (name || "class"), buf, len);
              } catch (e) {}
            }
          },
        });

        // ---- ThrowNew (14) / ExceptionOccurred (15) ----
        // ThrowNew(env, jclass, char* message) - args[2]=message string. Anti-analysis code
        // frequently throws with revealing messages ("frida detected", "emulator", ...).
        attachSlot(14, "ThrowNew", {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const msg = readStrSafe(args[2]);
            if (!msg) return;
            const ctx = this.context;
            scan("JNI ThrowNew", msg, () => getNativeBacktrace(ctx));
          },
        });
        // ExceptionOccurred(env) takes no string args; log occurrences (deduped by call
        // site) as a weak anti-analysis signal from target callers only, so a hot
        // exception-check loop cannot flood the console. Emitted at dump (PURPLE) severity,
        // matching the legacy PURPLE print.
        attachSlot(15, "ExceptionOccurred", {
          onEnter: function (this: IC) {
            if (!isTargetCaller(this.returnAddress)) return;
            let site = "";
            try {
              site = DebugSymbol.fromAddress(this.returnAddress).toString();
            } catch (e) {}
            const signature = "JNI ExceptionOccurred|" + site;
            if (hasSeen(signature)) return;
            markSeen(signature);
            log.detect("JNI ExceptionOccurred", "from " + (site || this.returnAddress));
          },
        });

        log.setup(TAG, "Extended JNIEnv vtable hooks installed.");
      } catch (e: any) {
        log.warn(TAG, "Failed to install extended JNIEnv hooks: " + e.message);
      }
    });
  },
};

export default mod;
