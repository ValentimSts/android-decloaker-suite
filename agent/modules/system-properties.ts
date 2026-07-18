// Ported from legacy decloaker.js hookSystemProperties (lines 400-459).
//
// Hooks __system_property_get, the libc entry point apps use to read
// ro.*/gsm.* build-fingerprint properties. Purely observational unless
// config.activeBypass is on, in which case a handful of well-known
// emulator-tell properties get their value buffer overwritten in place.

import { config } from "../config";
import { log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { getExportSafe, readStrSafe } from "../core/memory";
import type { IC, DecloakerModule } from "../types";

const TAG = "SYS-PROP";

const mod: DecloakerModule = {
  id: "system-properties",
  tag: TAG,
  description: "Hooks __system_property_get to detect and spoof ro.*/gsm.* property queries",
  enabledByDefault: true,
  install() {
    const sysPropGet = getExportSafe("libc.so", "__system_property_get");
    if (!sysPropGet) return;

    Interceptor.attach(sysPropGet, {
      // onEnter/onLeave share state via `this` (per-call InvocationContext),
      // so both MUST stay classic functions - an arrow here would share one
      // `this` across every call instead of getting a fresh one each time.
      onEnter: function (this: IC, args) {
        this.propName = readStrSafe(args[0]);
        this.valBuf = args[1];
      },
      onLeave: function (this: IC) {
        const propName: string = this.propName;
        const valBuf: NativePointer = this.valBuf;
        if (!propName || (propName.indexOf("ro.") !== 0 && propName.indexOf("gsm.") !== 0)) return;

        let propValue = "";
        if (valBuf && !valBuf.isNull()) {
          propValue = readStrSafe(valBuf);
        }

        // Check if we have seen this exact property query before.
        const sig = "sysprop_get|" + propName;
        const seen = hasSeen(sig);

        // We MUST perform the writeUtf8String every time so the target app
        // gets the fake value, but we only log the bypass on first sight.
        if (config.activeBypass && valBuf && !valBuf.isNull()) {
          if (propName === "ro.arch") {
            if (!seen) log.bypass(TAG, "Spoofing ro.arch to arm64-v8a");
            valBuf.writeUtf8String("arm64-v8a");
            propValue = "arm64-v8a";
          } else if (propName === "ro.build.version.codename") {
            if (!seen) log.bypass(TAG, "Spoofing ro.build.version.codename to REL");
            valBuf.writeUtf8String("REL");
            propValue = "REL";
          } else if (propName === "ro.input.resampling") {
            if (!seen) log.bypass(TAG, "Spoofing ro.input.resampling to 1");
            valBuf.writeUtf8String("1");
            propValue = "1";
          } else if (propName === "ro.build.version.release") {
            if (!seen) log.bypass(TAG, "Spoofing ro.build.version.release to 14");
            valBuf.writeUtf8String("14");
            propValue = "14";
          } else if (propName === "ro.build.version.sdk") {
            if (!seen) log.bypass(TAG, "Spoofing ro.build.version.sdk to 34");
            valBuf.writeUtf8String("34");
            propValue = "34";
          }
        }

        // Stop here if we've already logged this property.
        if (seen) return;
        markSeen(sig);

        log.detect(TAG, "__system_property_get", [
          ["Queried", propName + " = " + (propValue ? propValue : "[empty]")],
        ]);
      },
    });

    log.setup(TAG, "Hooked Native System Properties (__system_property_get)");
  },
};

export default mod;
