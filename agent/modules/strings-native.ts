// Ported from legacy decloaker.js hookStringsNative (lines 950-1086).
//
// A native CModule (TinyCC) that scans the output of hot libc string routines
// for TARGET_STRINGS. strcpy/strcat receive the final substring directly in
// arg1; sprintf/snprintf assemble it into the destination buffer (arg0), read
// on leave. A case-insensitive substring search is implemented inline because
// TinyCC cannot link libc strcasestr on Android. A match calls back into JS
// (onMatch), which attributes the site via the explicitly-passed return address
// (there is no valid Interceptor CpuContext inside a CModule NativeCallback) and
// routes through the shared matcher. The module also installs a native strstr
// NULL-argument guard for stability. Disabled by default.

import { log } from "../core/logger";
import { getExportSafe, readStrSafe } from "../core/memory";
import { isTargetCaller } from "../core/backtrace";
import { scan } from "../filters/matcher";
import { TARGET_STRINGS } from "../filters/lexicon";
import type { DecloakerModule } from "../types";

const TAG = "CModule";

// void onMatch(const char *str, const char *funcName, void *returnAddress)
type OnMatchCallback = NativeCallback<"void", ["pointer", "pointer", "pointer"]>;

const mod: DecloakerModule = {
  id: "strings-native",
  tag: TAG,
  description:
    "Native CModule scanning strcpy/strcat/sprintf/snprintf output for target strings, plus a strstr NULL-argument guard",
  enabledByDefault: false,
  install() {
    // targets[] are lowercased on the JS side; num_targets sizes the C array.
    // Both are interpolated into the C source at assembly time.
    const targetsC = TARGET_STRINGS.map(function (s) {
      return '"' + s.toLowerCase() + '"';
    }).join(", ");

    const cCode = `
    #include <gum/guminterceptor.h>
    #include <string.h>

    extern void onMatch(const char *str, const char *funcName, void *returnAddress);

    const char *targets[] = { ${targetsC} };
    const int num_targets = ${TARGET_STRINGS.length};

    // cap: destination buffer size. -1 = unbounded (sprintf always NUL-terminates on success);
    // for snprintf it is the caller's size argument, so cap == 0 means dest was never written.
    typedef struct { const char *dest; long cap; } SprintfState;

    // Case-insensitive substring search, implemented inline: Frida's CModule (TinyCC) cannot link
    // libc strcasestr on Android (undefined symbol at link time). This scans the FULL, unbounded
    // string with no fixed buffer and no in-place mutation of the (possibly read-only) source.
    // targets[] are already lowercased on the JS side.
    static int ci_contains(const char *hay, const char *needle) {
        if (!hay || !needle || !*needle) return 0;
        for (; *hay; hay++) {
            const char *h = hay;
            const char *n = needle;
            while (*h && *n) {
                char ch = *h;
                char cn = *n;
                if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
                if (cn >= 'A' && cn <= 'Z') cn = (char)(cn + 32);
                if (ch != cn) break;
                h++; n++;
            }
            if (!*n) return 1;
        }
        return 0;
    }

    static void scan_and_report(const char *src, const char *funcName, GumInvocationContext *ic) {
        if (!src) return;
        for (int i = 0; i < num_targets; i++) {
            if (ci_contains(src, targets[i])) {
                void *retAddr = gum_invocation_context_get_return_address(ic);
                onMatch(src, funcName, retAddr);
                return;
            }
        }
    }

    // strcpy/strcat: the source argument (arg 1) already holds the final substring.
    void on_strcpy(GumInvocationContext *ic) {
        scan_and_report((const char *) gum_invocation_context_get_nth_argument(ic, 1), "strcpy", ic);
    }
    void on_strcat(GumInvocationContext *ic) {
        scan_and_report((const char *) gum_invocation_context_get_nth_argument(ic, 1), "strcat", ic);
    }

    // sprintf/snprintf: the ASSEMBLED output lives in the destination buffer (arg 0), only valid
    // AFTER the call. Capture dest (+ snprintf's size) on enter, scan on leave. Guard against a
    // never-written destination (snprintf size 0, or a negative return) to avoid an OOB read.
    static void scan_output(GumInvocationContext *ic, const char *funcName) {
        SprintfState *s = (SprintfState *) gum_invocation_context_get_listener_invocation_data(ic, sizeof(SprintfState));
        int ret = (int) (size_t) gum_invocation_context_get_return_value(ic);
        if (ret < 0) return;      // encoding error: destination contents are indeterminate
        if (s->cap == 0) return;  // snprintf(dest, 0, ...): destination was never touched
        scan_and_report(s->dest, funcName, ic);
    }
    void on_sprintf_enter(GumInvocationContext *ic) {
        SprintfState *s = (SprintfState *) gum_invocation_context_get_listener_invocation_data(ic, sizeof(SprintfState));
        s->dest = (const char *) gum_invocation_context_get_nth_argument(ic, 0);
        s->cap = -1;
    }
    void on_sprintf_leave(GumInvocationContext *ic) { scan_output(ic, "sprintf"); }
    void on_snprintf_enter(GumInvocationContext *ic) {
        SprintfState *s = (SprintfState *) gum_invocation_context_get_listener_invocation_data(ic, sizeof(SprintfState));
        s->dest = (const char *) gum_invocation_context_get_nth_argument(ic, 0);
        s->cap = (long) gum_invocation_context_get_nth_argument(ic, 1);
    }
    void on_snprintf_leave(GumInvocationContext *ic) { scan_output(ic, "snprintf"); }

    // Stability guard for strstr: buggy graphics/emulator code (e.g. libEGL calling
    // strstr(eglQueryString(...)==NULL, needle)) and some malware call strstr with a NULL
    // argument, which crashes libc (NULL deref in strchr). Point any NULL argument at a static
    // empty string so the call returns safely (NULL / haystack) instead of faulting.
    static const char EMPTY_STR[1] = { 0 };
    void guard_strstr(GumInvocationContext *ic) {
        if (gum_invocation_context_get_nth_argument(ic, 0) == 0)
            gum_invocation_context_replace_nth_argument(ic, 0, (gpointer) EMPTY_STR);
        if (gum_invocation_context_get_nth_argument(ic, 1) == 0)
            gum_invocation_context_replace_nth_argument(ic, 1, (gpointer) EMPTY_STR);
    }
    `;

    try {
      const onMatch: OnMatchCallback = new NativeCallback(
        function (strPtr, funcPtr, retAddr) {
          if (!isTargetCaller(retAddr)) return;
          const str = readStrSafe(strPtr);
          const func = readStrSafe(funcPtr);
          // No valid Interceptor CpuContext inside a CModule NativeCallback; attribute the
          // call via the explicitly-passed return address instead of an unreliable backtrace.
          let site = "";
          try {
            site = DebugSymbol.fromAddress(retAddr).toString();
          } catch (e) {}
          scan("[CModule] " + func + (site ? " @ " + site : ""), str);
        },
        "void",
        ["pointer", "pointer", "pointer"]
      );

      const cm = new CModule(cCode, { onMatch });

      const handlers: Record<string, NativeInvocationListenerCallbacks> = {
        strcpy: { onEnter: cm.on_strcpy },
        strcat: { onEnter: cm.on_strcat },
        sprintf: { onEnter: cm.on_sprintf_enter, onLeave: cm.on_sprintf_leave },
        snprintf: { onEnter: cm.on_snprintf_enter, onLeave: cm.on_snprintf_leave },
      };
      for (const fn of Object.keys(handlers)) {
        const p = getExportSafe("libc.so", fn);
        if (p) Interceptor.attach(p, handlers[fn]);
      }

      // Stability guard: protect strstr against NULL arguments (a libc NULL-deref crash seen
      // when the emulator's libEGL calls strstr on a NULL extension string). Native onEnter,
      // so no per-call JS overhead on this very hot function.
      try {
        const strstrPtr = getExportSafe("libc.so", "strstr");
        if (strstrPtr && cm.guard_strstr) {
          // BUG: Commented out to to stop crashing libEGL!
          Interceptor.attach(strstrPtr, { onEnter: cm.guard_strstr });
          log.setup(TAG, "Installed strstr NULL-argument guard");
        }
      } catch (e: any) {
        log.warn(TAG, "Could not install strstr guard: " + e.message);
      }

      log.setup(TAG, "Native CModule injected for high-performance string matching.");
    } catch (e: any) {
      log.warn(TAG, "Failed to compile CModule string hooks: " + e.message);
    }
  },
};

export default mod;
