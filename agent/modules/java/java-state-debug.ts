// Ported from legacy decloaker.js hookJavaStateAndDebug + hookSqliteNative
// (lines 5443-5675), plus the module-private SQLITE_MAX_TEXT constant and the
// prefsLog dedup/truncate helper (hoisted to module scope; legacy nested it in
// Java.perform, but it closes over nothing Java-specific).
//
// Three concerns share this module:
//   ANTI-DEBUG  android.os.Debug / dalvik.system.VMDebug isDebuggerConnected +
//               waitingForDebugger. Detection-only unless config.activeBypass is
//               on, in which case the debugger-connected checks are forced to
//               report "no debugger" so the sample proceeds with real behavior.
//   PREFS       android.app.SharedPreferencesImpl get/putString/getBoolean -
//               persisted C2 endpoints, install flags, kill-switches. Value is
//               logged once per (kind|key) and truncated; scan() still runs
//               per-call for lexicon detection.
//   SQLITE      native libsqlite.so sqlite3_open_v2 / prepare_v2 / bind_text -
//               stolen-data DB path, prepared SQL, and the concrete values bound
//               behind '?' placeholders. Detection-only, caller-gated.
//
// hookSqliteNative runs first and does NOT need Java, so it installs even when
// the Java VM is unavailable - matching the legacy ordering exactly.

import { config } from "../../config";
import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { getExportSafe, readStrSafe } from "../../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../../core/backtrace";
import { scan } from "../../filters/matcher";
import { Java, withJava } from "../../core/java";
import type { IC, DecloakerModule } from "../../types";

// Legacy embedded three inline log tags: ANTI-DEBUG, PREFS, SQLITE. All three
// preserved here; mod.tag reports the primary one (ANTI-DEBUG).
const TAG_ANTIDEBUG = "ANTI-DEBUG";
const TAG_PREFS = "PREFS";
const TAG_SQLITE = "SQLITE";

// Upper bound on how many bytes we ever read from a caller-supplied SQLite length.
// A hostile / bogus nByte (huge or negative-cast) must not trigger a pathological
// or OOB read; readStrSafe additionally catches faults, so at worst we truncate
// over-long text.
const SQLITE_MAX_TEXT = 262144;

// getString is called very frequently for routine config reads, so log at most
// once per (kind|key) and truncate the value - otherwise this floods the console
// with full, possibly-large stored blobs. scan() (at the call sites) still runs
// per-call for detection. Legacy's ALERT_HISTORY[sig] truthiness maps to hasSeen.
function prefsLog(kind: string, key: string, val: any): void {
  const sig = "prefs|" + kind + "|" + key;
  if (hasSeen(sig)) return;
  markSeen(sig);
  let v = "" + val;
  if (v.length > 300) v = v.substring(0, 300) + "...[truncated]";
  log.dump(TAG_PREFS, kind + "(" + key + ") -> " + v);
}

// Native libsqlite.so hooks. Detection-only (never spoofs): sqlite3_open_v2
// exposes the on-disk DB path (stolen-data / staging DBs), sqlite3_prepare_v2
// exposes the SQL text (including '?' placeholders), and sqlite3_bind_text
// exposes the ACTUAL values substituted behind those placeholders (exfiltrated
// fields). Frequency gating: narrowed by isTargetCaller(this.returnAddress)
// module gating; bind_text additionally only surfaces via scan (which prints
// only on a lexicon match), so it never floods on ordinary parameter binds.
function hookSqliteNative(): void {
  // sqlite3_open_v2(filename, ppDb, flags, zVfs): path is arg0 (NUL-terminated).
  const openPtr = getExportSafe("libsqlite.so", "sqlite3_open_v2");
  if (openPtr) {
    try {
      Interceptor.attach(openPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) return;
          const path = readStrSafe(args[0]);
          if (!path) return;
          // Capture ctx: the trace thunk is called bare (never via `this`) by scan.
          const ctx = this.context;
          log.dump(TAG_SQLITE, "sqlite3_open_v2 -> " + path);
          scan("sqlite3_open_v2", path, () => getNativeBacktrace(ctx));
        },
      });
      log.setup(TAG_SQLITE, "Hooked SQLite: sqlite3_open_v2");
    } catch (e: any) {
      log.warn(TAG_SQLITE, "Failed to hook sqlite3_open_v2: " + e.message);
    }
  }

  // sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail): SQL text is arg1.
  // nByte (arg2) may be -1 (NUL-terminated) or an explicit byte length; when it is
  // a sane positive value use it, otherwise fall back to a NUL-terminated read.
  const prepPtr = getExportSafe("libsqlite.so", "sqlite3_prepare_v2");
  if (prepPtr) {
    try {
      Interceptor.attach(prepPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) return;
          let nByte = -1;
          try {
            nByte = args[2].toInt32();
          } catch (e) {}
          const sql =
            nByte > 0 && nByte <= SQLITE_MAX_TEXT ? readStrSafe(args[1], nByte) : readStrSafe(args[1]);
          if (!sql) return;
          const ctx = this.context;
          log.info(TAG_SQLITE, "sqlite3_prepare_v2 -> " + sql);
          scan("sqlite3_prepare_v2", sql, () => getNativeBacktrace(ctx));
        },
      });
      log.setup(TAG_SQLITE, "Hooked SQLite: sqlite3_prepare_v2");
    } catch (e: any) {
      log.warn(TAG_SQLITE, "Failed to hook sqlite3_prepare_v2: " + e.message);
    }
  }

  // sqlite3_bind_text(stmt, index, value, nBytes, destructor): value is arg2,
  // length arg3. This reveals the concrete data substituted for '?' placeholders
  // in prepared statements - i.e. the actual field values being written to /
  // queried from the stolen-data DB.
  const bindPtr = getExportSafe("libsqlite.so", "sqlite3_bind_text");
  if (bindPtr) {
    try {
      Interceptor.attach(bindPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) return;
          let nBytes = -1;
          try {
            nBytes = args[3].toInt32();
          } catch (e) {}
          const val =
            nBytes > 0 && nBytes <= SQLITE_MAX_TEXT ? readStrSafe(args[2], nBytes) : readStrSafe(args[2]);
          // Content gating: skip empty binds entirely; scan only surfaces (and
          // dedups) values that match the lexicon, so routine binds stay silent.
          if (!val) return;
          const ctx = this.context;
          scan("sqlite3_bind_text", val, () => getNativeBacktrace(ctx));
        },
      });
      log.setup(TAG_SQLITE, "Hooked SQLite: sqlite3_bind_text");
    } catch (e: any) {
      log.warn(TAG_SQLITE, "Failed to hook sqlite3_bind_text: " + e.message);
    }
  }
}

const mod: DecloakerModule = {
  id: "java-state-debug",
  tag: TAG_ANTIDEBUG,
  description:
    "Hooks Java anti-debug (Debug/VMDebug), SharedPreferences state reads/writes, and native libsqlite.so",
  enabledByDefault: false,
  install() {
    // Native SQLite hooks first: they do not require the Java VM, so they must
    // install even when Java is unavailable (legacy ordering preserved).
    hookSqliteNative();

    // Legacy emitted an explicit warning here on missing Java (unlike the silent
    // withJava guard), so preserve it before deferring to withJava.
    if (!Java.available) {
      log.warn(TAG_ANTIDEBUG, "Java is not available. Skipping anti-debug/state hooks.");
      return;
    }

    withJava(() => {
      // ---- android.os.Debug: isDebuggerConnected / waitingForDebugger ----
      // Both are static and take no args. Inside a Frida .implementation override,
      // this.<method>() dispatches to the ORIGINAL (un-hooked) impl - no recursion.
      // Under activeBypass we return false so the sample believes no debugger/JDWP
      // is attached and proceeds with real behavior.
      try {
        const Debug = Java.use("android.os.Debug");
        try {
          Debug.isDebuggerConnected.implementation = function (this: any) {
            const real = this.isDebuggerConnected();
            log.detect(TAG_ANTIDEBUG, "Debug.isDebuggerConnected() -> " + real);
            if (config.activeBypass) {
              log.bypass(TAG_ANTIDEBUG, "Forcing Debug.isDebuggerConnected() = false");
              return false;
            }
            return real;
          };
        } catch (e: any) {
          log.warn(TAG_ANTIDEBUG, "Could not hook Debug.isDebuggerConnected: " + e.message);
        }
        try {
          Debug.waitingForDebugger.implementation = function (this: any) {
            const real = this.waitingForDebugger();
            log.detect(TAG_ANTIDEBUG, "Debug.waitingForDebugger() -> " + real);
            if (config.activeBypass) {
              log.bypass(TAG_ANTIDEBUG, "Forcing Debug.waitingForDebugger() = false");
              return false;
            }
            return real;
          };
        } catch (e: any) {
          log.warn(TAG_ANTIDEBUG, "Could not hook Debug.waitingForDebugger: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG_ANTIDEBUG, "Could not use android.os.Debug: " + e.message);
      }

      // ---- dalvik.system.VMDebug.isDebuggerConnected (static, no args) ----
      // This is the native method android.os.Debug.isDebuggerConnected() delegates
      // to; hooking it catches callers that reach the runtime directly. Individually
      // guarded in case a given ART build does not expose it.
      try {
        const VMDebug = Java.use("dalvik.system.VMDebug");
        try {
          VMDebug.isDebuggerConnected.implementation = function (this: any) {
            const real = this.isDebuggerConnected();
            log.detect(TAG_ANTIDEBUG, "VMDebug.isDebuggerConnected() -> " + real);
            if (config.activeBypass) {
              log.bypass(TAG_ANTIDEBUG, "Forcing VMDebug.isDebuggerConnected() = false");
              return false;
            }
            return real;
          };
        } catch (e: any) {
          log.warn(TAG_ANTIDEBUG, "Could not hook VMDebug.isDebuggerConnected: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG_ANTIDEBUG, "Could not use dalvik.system.VMDebug: " + e.message);
      }

      // ---- android.app.SharedPreferencesImpl: getString / getBoolean (reads) ----
      // Malware persists C2 endpoints, install flags, first-run markers, kill-switches
      // here. Log key + returned value and run both through scan for salient tokens.
      try {
        const SPImpl = Java.use("android.app.SharedPreferencesImpl");
        try {
          SPImpl.getString.overload("java.lang.String", "java.lang.String").implementation = function (
            this: any,
            key: any,
            defVal: any
          ) {
            const val = this.getString(key, defVal);
            prefsLog("getString", "" + key, val);
            scan("SharedPreferences.getString.key", "" + key);
            if (val !== null) scan("SharedPreferences.getString.value", "" + val);
            return val;
          };
        } catch (e: any) {
          log.warn(TAG_PREFS, "Could not hook SharedPreferencesImpl.getString: " + e.message);
        }
        try {
          SPImpl.getBoolean.overload("java.lang.String", "boolean").implementation = function (
            this: any,
            key: any,
            defVal: any
          ) {
            const val = this.getBoolean(key, defVal);
            prefsLog("getBoolean", "" + key, val);
            scan("SharedPreferences.getBoolean.key", "" + key);
            return val;
          };
        } catch (e: any) {
          log.warn(TAG_PREFS, "Could not hook SharedPreferencesImpl.getBoolean: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG_PREFS, "Could not use android.app.SharedPreferencesImpl: " + e.message);
      }

      // ---- android.app.SharedPreferencesImpl$EditorImpl.putString (writes) ----
      // Captures newly-stored config/flags (e.g. saved C2, campaign IDs) as written.
      try {
        const EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        try {
          EditorImpl.putString.overload("java.lang.String", "java.lang.String").implementation = function (
            this: any,
            key: any,
            value: any
          ) {
            prefsLog("putString", "" + key, value);
            scan("SharedPreferences.putString.key", "" + key);
            if (value !== null) scan("SharedPreferences.putString.value", "" + value);
            return this.putString(key, value);
          };
        } catch (e: any) {
          log.warn(TAG_PREFS, "Could not hook EditorImpl.putString: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG_PREFS, "Could not use SharedPreferencesImpl$EditorImpl: " + e.message);
      }

      log.setup(
        TAG_ANTIDEBUG,
        "Hooked Java anti-debug (Debug/VMDebug) and persistent state (SharedPreferences)"
      );
    });
  },
};

export default mod;
