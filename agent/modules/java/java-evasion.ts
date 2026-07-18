// Ported from legacy decloaker.js hookJavaEvasionAPIs (lines 1334-1473).
//
// Java-layer emulator/sandbox detection that never touches the native hooks:
// Settings.Secure/Settings.Global keys (adb_enabled, development_settings_enabled),
// telephony operators, sensor vendors, and BatteryManager/Intent battery properties
// (100% capacity / always-charging) that give an emulator or sandbox away.

import { config } from "../../config";
import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { Java, withJava } from "../../core/java";
import { scan } from "../../filters/matcher";
import type { DecloakerModule } from "../../types";

// Legacy embedded two distinct log tags inline: TELEPHONY (operator/sensor
// announcements) and BATTERY (BatteryManager/Intent capacity + charging tells).
// Both preserved here. mod.tag reports the primary one.
const TAG_TELEPHONY = "TELEPHONY";
const TAG_BATTERY = "BATTERY";

const mod: DecloakerModule = {
  id: "java-evasion",
  tag: TAG_TELEPHONY,
  description: "Hooks Settings/TelephonyManager/SensorManager/BatteryManager Java APIs used for emulator detection",
  enabledByDefault: true,
  requires: "java",
  install() {
    // withJava does the legacy `if (!Java.available) return;` guard silently,
    // then Java.perform - matching the legacy body exactly (no warn emitted).
    withJava(() => {
      // Settings.Secure / Settings.Global getString(): catches queries for
      // adb_enabled, development_settings_enabled and similar emulator tells.
      // scan()'s source arg becomes the detection log tag (legacy checkAndLog).
      ["android.provider.Settings$Secure", "android.provider.Settings$Global"].forEach(function (cls) {
        try {
          const S = Java.use(cls);
          S.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function (
            this: any,
            cr: any,
            key: any
          ) {
            scan(cls + ".getString", key);
            return this.getString(cr, key);
          };
        } catch (e: any) {
          log.warn(TAG_TELEPHONY, "Could not hook " + cls + ".getString: " + e.message);
        }
      });

      try {
        const TM = Java.use("android.telephony.TelephonyManager");
        ["getSimOperator", "getNetworkOperator", "getSimCountryIso"].forEach(function (m) {
          try {
            // Announcement is unconditional (no hasSeen/markSeen gate) - matches
            // legacy, which logged every call here; scan() below still dedupes.
            TM[m].overload().implementation = function (this: any) {
              const v = this[m]();
              log.detect(TAG_TELEPHONY, m + "() -> " + v);
              scan("TelephonyManager." + m, "" + v);
              return v;
            };
          } catch (e) {}
        });
      } catch (e: any) {
        log.warn(TAG_TELEPHONY, "Could not hook TelephonyManager: " + e.message);
      }

      try {
        const SM = Java.use("android.hardware.SensorManager");
        SM.getDefaultSensor.overload("int").implementation = function (this: any, type: any) {
          const sensor = this.getDefaultSensor(type);
          if (sensor !== null) {
            try {
              scan("SensorManager.getDefaultSensor", sensor.getName() + " / " + sensor.getVendor());
            } catch (e) {}
          }
          return sensor;
        };
      } catch (e: any) {
        log.warn(TAG_TELEPHONY, "Could not hook SensorManager: " + e.message);
      }

      // ---- BatteryManager & Intent checks (emulator detection) ----
      try {
        const BatteryManager = Java.use("android.os.BatteryManager");

        // Hook direct capacity checks.
        BatteryManager.getIntProperty.overload("int").implementation = function (this: any, id: any) {
          const val = this.getIntProperty(id);
          // 4 = BATTERY_PROPERTY_CAPACITY
          if (id === 4) {
            const sig = "battery_manager_capacity";
            // Snapshot BEFORE marking: this first call still logs as the initial
            // sighting even though markSeen() below takes effect immediately, so
            // every later call sees seen=true.
            const seen = hasSeen(sig);
            if (!seen) markSeen(sig);

            if (!seen) {
              log.detect(TAG_BATTERY, "BatteryManager.getIntProperty(CAPACITY) queried", [
                ["Original Value", val + "%"],
              ]);
            }

            if (config.activeBypass) {
              if (!seen) log.bypass(TAG_BATTERY, "Spoofing battery capacity to 83%");
              return 83; // Spoof a realistic battery level
            }
          }
          return val;
        };

        // Hook direct charging status checks.
        try {
          BatteryManager.isCharging.overload().implementation = function (this: any) {
            const val = this.isCharging();
            const sig = "battery_manager_ischarging";
            const seen = hasSeen(sig);
            if (!seen) markSeen(sig);

            if (!seen) {
              log.detect(TAG_BATTERY, "BatteryManager.isCharging() queried", [["Original Value", "" + val]]);
            }

            if (config.activeBypass) {
              if (!seen) log.bypass(TAG_BATTERY, "Spoofing isCharging to false");
              return false; // Spoof unplugged status
            }
            return val;
          };
        } catch (e) {}
      } catch (e: any) {
        log.warn(TAG_BATTERY, "Could not hook BatteryManager: " + e.message);
      }

      // Hook Intent extras (used when registering receivers for ACTION_BATTERY_CHANGED).
      try {
        const Intent = Java.use("android.content.Intent");
        Intent.getIntExtra.overload("java.lang.String", "int").implementation = function (
          this: any,
          name: any,
          def: any
        ) {
          const val = this.getIntExtra(name, def);

          if (name === "level" || name === "plugged") {
            let action = "";
            try {
              action = this.getAction();
            } catch (e) {}

            if (action === "android.intent.action.BATTERY_CHANGED") {
              const sig = "battery_intent|" + name;
              const seen = hasSeen(sig);
              if (!seen) markSeen(sig);

              if (!seen) {
                log.detect(TAG_BATTERY, "Intent.getIntExtra('" + name + "') queried from BATTERY_CHANGED", [
                  ["Original Value", "" + val],
                ]);
              }

              if (config.activeBypass) {
                if (name === "level") {
                  if (!seen) log.bypass(TAG_BATTERY, "Spoofing battery level to 83");
                  return 83;
                } else if (name === "plugged") {
                  // 0 = unplugged (running on battery); emulators are usually AC (1) or USB (2).
                  if (!seen) log.bypass(TAG_BATTERY, "Spoofing battery plugged status to 0 (Unplugged)");
                  return 0;
                }
              }
            }
          }
          return val;
        };
      } catch (e: any) {
        log.warn(TAG_BATTERY, "Could not hook Intent.getIntExtra: " + e.message);
      }

      log.setup(TAG_TELEPHONY, "Hooked Java evasion APIs (Settings, Telephony, Sensors, Battery)");
    });
  },
};

export default mod;
