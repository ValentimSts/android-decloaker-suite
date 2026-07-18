// Ported from legacy decloaker.js hookBehaviorIPC (lines 4985-5442).
//
// Java-layer behavioral hooks: SMS fraud, accessibility abuse (keylogging/auto-click),
// content resolver access to sensitive providers, command execution, package/process
// enumeration, activity/broadcast/receiver IPC, and clipboard theft. These are Java APIs
// (not hot native paths), so no isTargetCaller gating is needed; per file convention Java
// hooks pass no trace callback to scan().
// Each Java.use and each .overload is individually wrapped in try/catch that logs a
// one-line failure - no silent empty catches.
//
// Exception: onAccessibilityEvent fires on EVERY UI event (keystrokes included), so it is
// dedup-gated via the shared hasSeen/markSeen (keyed on event type + package) to avoid
// flooding the console and hanging the app UI - the one hot path in an otherwise cold module.

import { config } from "../../config";
import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { Java, withJava } from "../../core/java";
import { scan } from "../../filters/matcher";
import type { DecloakerModule } from "../../types";

const TAG = "BEHAVIOR-IPC";

const mod: DecloakerModule = {
  id: "behavior-ipc",
  tag: TAG,
  description:
    "Detects SMS fraud, accessibility abuse, sensitive content access, exec, package/process enumeration, IPC, and clipboard theft",
  enabledByDefault: true,
  requires: "java",
  install() {
    // withJava does the legacy `if (!Java.available) return;` guard silently,
    // then Java.perform - matching the legacy body (the module is already gated
    // on Java.available at dispatch via `requires: "java"`).
    withJava(() => {
      // Truncate long argument values for readable logs (avoids flooding on big bodies/argv).
      function preview(v: any): string {
        let s = v === null || v === undefined ? "" : "" + v;
        if (s.length > 300) s = s.substring(0, 300) + "...[TRUNCATED]";
        return s;
      }

      // Report a behavioral event and run the salient string(s) through the lexicon.
      // Nested (not module-scope) because it closes over preview() and is the shared
      // sink every hook below funnels its finding through.
      function report(tag: string, label: string, value: any): void {
        const present = value !== null && value !== undefined && value !== "";
        const fields: [string, string][] | undefined = present ? [["Value", preview(value)]] : undefined;
        log.detect(tag, label, fields);
        if (present) {
          scan(tag, "" + value);
        }
      }

      // ---- SMS fraud: android.telephony.SmsManager ----
      try {
        const SmsManager = Java.use("android.telephony.SmsManager");

        try {
          SmsManager.sendTextMessage
            .overload(
              "java.lang.String",
              "java.lang.String",
              "java.lang.String",
              "android.app.PendingIntent",
              "android.app.PendingIntent"
            )
            .implementation = function (this: any, dest: any, sc: any, body: any, sent: any, delivered: any) {
            report("SMS", "SmsManager.sendTextMessage -> " + dest, body);
            return this.sendTextMessage(dest, sc, body, sent, delivered);
          };
        } catch (e: any) {
          log.warn("SMS", "SmsManager.sendTextMessage hook unavailable: " + e.message);
        }

        try {
          SmsManager.sendMultipartTextMessage
            .overload(
              "java.lang.String",
              "java.lang.String",
              "java.util.ArrayList",
              "java.util.ArrayList",
              "java.util.ArrayList"
            )
            .implementation = function (
            this: any,
            dest: any,
            sc: any,
            parts: any,
            sentIntents: any,
            deliveryIntents: any
          ) {
            let joined = "";
            try {
              if (parts !== null) {
                const n = parts.size();
                for (let i = 0; i < n; i++) {
                  joined += (i ? " " : "") + parts.get(i);
                }
              }
            } catch (e) {}
            report("SMS", "SmsManager.sendMultipartTextMessage -> " + dest, joined);
            return this.sendMultipartTextMessage(dest, sc, parts, sentIntents, deliveryIntents);
          };
        } catch (e: any) {
          log.warn("SMS", "SmsManager.sendMultipartTextMessage hook unavailable: " + e.message);
        }

        try {
          SmsManager.sendDataMessage
            .overload(
              "java.lang.String",
              "java.lang.String",
              "short",
              "[B",
              "android.app.PendingIntent",
              "android.app.PendingIntent"
            )
            .implementation = function (this: any, dest: any, sc: any, port: any, data: any, sent: any, delivered: any) {
            let len: string | number = "unknown";
            try {
              len = data === null ? "null" : data.length;
            } catch (e) {}
            report("SMS", "SmsManager.sendDataMessage -> " + dest + " (port " + port + ")", "binary data length=" + len);
            return this.sendDataMessage(dest, sc, port, data, sent, delivered);
          };
        } catch (e: any) {
          log.warn("SMS", "SmsManager.sendDataMessage hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("SMS", "Could not hook android.telephony.SmsManager: " + e.message);
      }

      // ---- Accessibility abuse: keylogging / auto-click ----
      try {
        const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

        // onAccessibilityEvent fires on EVERY UI event (extremely high frequency), so it MUST be
        // gated. We dedup on the shared dedup store keyed by event type + source package: the
        // first occurrence of each (type,pkg) raises a detect alert; all later ones only run the
        // event text through scan() (which has its own dedup) - never a per-keystroke flood.
        try {
          AccessibilityService.onAccessibilityEvent
            .overload("android.view.accessibility.AccessibilityEvent")
            .implementation = function (this: any, event: any) {
            try {
              let pkg = "";
              let txt = "";
              let etype = "";
              if (event !== null) {
                try {
                  etype = "" + event.getEventType();
                } catch (e) {}
                try {
                  pkg = "" + event.getPackageName();
                } catch (e) {}
                try {
                  txt = "" + event.getText();
                } catch (e) {}
              }
              const sig = "a11yevt|" + etype + "|" + pkg;
              if (!hasSeen(sig)) {
                markSeen(sig);
                report("A11Y", "onAccessibilityEvent type=" + etype + " pkg=" + pkg, txt);
              } else {
                // Still lexicon-scan the text (cheap, deduped internally) without
                // emitting another behavioral alert for this (type,pkg) pair.
                scan("A11Y onAccessibilityEvent", txt);
              }
            } catch (e) {}
            return this.onAccessibilityEvent(event);
          };
        } catch (e: any) {
          log.warn("A11Y", "AccessibilityService.onAccessibilityEvent hook unavailable: " + e.message);
        }

        try {
          AccessibilityService.dispatchGesture
            .overload(
              "android.accessibilityservice.GestureDescription",
              "android.accessibilityservice.AccessibilityService$GestureResultCallback",
              "android.os.Handler"
            )
            .implementation = function (this: any, gesture: any, callback: any, handler: any) {
            report("A11Y", "dispatchGesture (auto-click/auto-input)", "gesture=" + gesture);
            return this.dispatchGesture(gesture, callback, handler);
          };
        } catch (e: any) {
          log.warn("A11Y", "AccessibilityService.dispatchGesture hook unavailable: " + e.message);
        }

        try {
          AccessibilityService.performGlobalAction.overload("int").implementation = function (
            this: any,
            action: any
          ) {
            report("A11Y", "performGlobalAction", "action=" + action);
            return this.performGlobalAction(action);
          };
        } catch (e: any) {
          log.warn("A11Y", "AccessibilityService.performGlobalAction hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("A11Y", "Could not hook android.accessibilityservice.AccessibilityService: " + e.message);
      }

      // ---- ContentResolver: sensitive provider access (sms/contacts/call_log) ----
      try {
        const ContentResolver = Java.use("android.content.ContentResolver");

        // Flag access to sensitive content:// authorities (SMS / contacts / call log).
        function flagSensitiveUri(where: string, uri: any): void {
          let u = "";
          try {
            u = uri === null ? "" : "" + uri;
          } catch (e) {
            u = "";
          }
          const lu = u.toLowerCase();
          const sensitive =
            lu.indexOf("content://sms") !== -1 ||
            lu.indexOf("content://mms") !== -1 ||
            lu.indexOf("contacts") !== -1 ||
            lu.indexOf("call_log") !== -1 ||
            lu.indexOf("calllog") !== -1;
          if (sensitive) {
            report("CONTENT", where + " SENSITIVE provider", u);
          } else {
            // Still run the uri through the lexicon (may hit e.g. vending/referrer tokens),
            // but do not raise a behavioral alert for ordinary providers.
            scan(where, u);
          }
        }

        // query has multiple overloads across API levels; hook them defensively.
        try {
          ContentResolver.query
            .overload(
              "android.net.Uri",
              "[Ljava.lang.String;",
              "java.lang.String",
              "[Ljava.lang.String;",
              "java.lang.String"
            )
            .implementation = function (this: any, uri: any, proj: any, sel: any, selArgs: any, sortOrder: any) {
            flagSensitiveUri("ContentResolver.query", uri);
            return this.query(uri, proj, sel, selArgs, sortOrder);
          };
        } catch (e: any) {
          log.warn("CONTENT", "ContentResolver.query(5-arg) hook unavailable: " + e.message);
        }

        try {
          ContentResolver.query
            .overload(
              "android.net.Uri",
              "[Ljava.lang.String;",
              "java.lang.String",
              "[Ljava.lang.String;",
              "java.lang.String",
              "android.os.CancellationSignal"
            )
            .implementation = function (
            this: any,
            uri: any,
            proj: any,
            sel: any,
            selArgs: any,
            sortOrder: any,
            sig: any
          ) {
            flagSensitiveUri("ContentResolver.query", uri);
            return this.query(uri, proj, sel, selArgs, sortOrder, sig);
          };
        } catch (e: any) {
          log.warn("CONTENT", "ContentResolver.query(6-arg) hook unavailable: " + e.message);
        }

        try {
          ContentResolver.query
            .overload("android.net.Uri", "[Ljava.lang.String;", "android.os.Bundle", "android.os.CancellationSignal")
            .implementation = function (this: any, uri: any, proj: any, queryArgs: any, sig: any) {
            flagSensitiveUri("ContentResolver.query", uri);
            return this.query(uri, proj, queryArgs, sig);
          };
        } catch (e: any) {
          log.warn("CONTENT", "ContentResolver.query(Bundle) hook unavailable: " + e.message);
        }

        try {
          ContentResolver.registerContentObserver
            .overload("android.net.Uri", "boolean", "android.database.ContentObserver")
            .implementation = function (this: any, uri: any, notifyDescendants: any, observer: any) {
            flagSensitiveUri("ContentResolver.registerContentObserver", uri);
            return this.registerContentObserver(uri, notifyDescendants, observer);
          };
        } catch (e: any) {
          log.warn("CONTENT", "ContentResolver.registerContentObserver hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("CONTENT", "Could not hook android.content.ContentResolver: " + e.message);
      }

      // ---- Command execution: Runtime.exec (all overloads) + ProcessBuilder.start ----
      try {
        const Runtime = Java.use("java.lang.Runtime");

        function argvToStr(argv: any): string {
          let s = "";
          try {
            if (argv !== null) {
              for (let i = 0; i < argv.length; i++) {
                s += (i ? " " : "") + argv[i];
              }
            }
          } catch (e) {}
          return s;
        }

        try {
          Runtime.exec.overload("java.lang.String").implementation = function (this: any, cmd: any) {
            report("EXEC", "Runtime.exec(String)", cmd);
            return this.exec(cmd);
          };
        } catch (e: any) {
          log.warn("EXEC", "Runtime.exec(String) hook unavailable: " + e.message);
        }

        try {
          Runtime.exec.overload("[Ljava.lang.String;").implementation = function (this: any, cmdarray: any) {
            report("EXEC", "Runtime.exec(String[])", argvToStr(cmdarray));
            return this.exec(cmdarray);
          };
        } catch (e: any) {
          log.warn("EXEC", "Runtime.exec(String[]) hook unavailable: " + e.message);
        }

        try {
          Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (
            this: any,
            cmd: any,
            envp: any
          ) {
            report("EXEC", "Runtime.exec(String, envp)", cmd);
            return this.exec(cmd, envp);
          };
        } catch (e: any) {
          log.warn("EXEC", "Runtime.exec(String,envp) hook unavailable: " + e.message);
        }

        try {
          Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;").implementation = function (
            this: any,
            cmdarray: any,
            envp: any
          ) {
            report("EXEC", "Runtime.exec(String[], envp)", argvToStr(cmdarray));
            return this.exec(cmdarray, envp);
          };
        } catch (e: any) {
          log.warn("EXEC", "Runtime.exec(String[],envp) hook unavailable: " + e.message);
        }

        try {
          Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;", "java.io.File").implementation = function (
            this: any,
            cmd: any,
            envp: any,
            dir: any
          ) {
            report("EXEC", "Runtime.exec(String, envp, dir)", cmd);
            return this.exec(cmd, envp, dir);
          };
        } catch (e: any) {
          log.warn("EXEC", "Runtime.exec(String,envp,dir) hook unavailable: " + e.message);
        }

        try {
          Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;",
            "java.io.File"
          ).implementation = function (this: any, cmdarray: any, envp: any, dir: any) {
            report("EXEC", "Runtime.exec(String[], envp, dir)", argvToStr(cmdarray));
            return this.exec(cmdarray, envp, dir);
          };
        } catch (e: any) {
          log.warn("EXEC", "Runtime.exec(String[],envp,dir) hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("EXEC", "Could not hook java.lang.Runtime.exec: " + e.message);
      }

      try {
        const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        try {
          ProcessBuilder.start.overload().implementation = function (this: any) {
            let cmd = "";
            try {
              const list = this.command();
              if (list !== null) {
                const n = list.size();
                for (let i = 0; i < n; i++) {
                  cmd += (i ? " " : "") + list.get(i);
                }
              }
            } catch (e) {}
            report("EXEC", "ProcessBuilder.start", cmd);
            return this.start();
          };
        } catch (e: any) {
          log.warn("EXEC", "ProcessBuilder.start hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("EXEC", "Could not hook java.lang.ProcessBuilder: " + e.message);
      }

      // ---- Package enumeration: ApplicationPackageManager ----
      try {
        const PM = Java.use("android.app.ApplicationPackageManager");

        ["getInstalledPackages", "getInstalledApplications"].forEach(function (m) {
          try {
            PM[m].overload("int").implementation = function (this: any, flags: any) {
              report("PKG", "PackageManager." + m + " (device app enumeration)", "flags=" + flags);
              return this[m](flags);
            };
          } catch (e: any) {
            log.warn("PKG", "PackageManager." + m + " hook unavailable: " + e.message);
          }
        });

        try {
          PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (
            this: any,
            pkg: any,
            flags: any
          ) {
            report("PKG", "PackageManager.getPackageInfo", pkg);
            return this.getPackageInfo(pkg, flags);
          };
        } catch (e: any) {
          log.warn("PKG", "PackageManager.getPackageInfo(String,int) hook unavailable: " + e.message);
        }

        try {
          PM.getInstallerPackageName.overload("java.lang.String").implementation = function (this: any, pkg: any) {
            // Read config.activeBypass LIVE (not snapshotted) so a runtime
            // rpc.setbypass() toggle takes effect on the very next call.
            if (config.activeBypass) {
              log.bypass("PKG", "Spoofing installer as Google Play Store (com.android.vending) for: " + pkg);
              return "com.android.vending";
            }
            const v = this.getInstallerPackageName(pkg);
            report("PKG", "PackageManager.getInstallerPackageName(" + pkg + ")", "" + v);
            return v;
          };
        } catch (e: any) {
          log.warn("PKG", "PackageManager.getInstallerPackageName hook unavailable: " + e.message);
        }

        try {
          PM.getInstallSourceInfo.overload("java.lang.String").implementation = function (this: any, pkg: any) {
            const v = this.getInstallSourceInfo(pkg);
            let inst = "";
            try {
              inst = "" + v.getInstallingPackageName();
            } catch (e) {}
            report("PKG", "PackageManager.getInstallSourceInfo(" + pkg + ")", "installer=" + inst);
            return v;
          };
        } catch (e: any) {
          log.warn("PKG", "PackageManager.getInstallSourceInfo hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("PKG", "Could not hook android.app.ApplicationPackageManager: " + e.message);
      }

      // ---- Process/service enumeration: ActivityManager ----
      try {
        const AM = Java.use("android.app.ActivityManager");
        try {
          AM.getRunningAppProcesses.overload().implementation = function (this: any) {
            report("PROC", "ActivityManager.getRunningAppProcesses (running process enumeration)", null);
            return this.getRunningAppProcesses();
          };
        } catch (e: any) {
          log.warn("PROC", "ActivityManager.getRunningAppProcesses hook unavailable: " + e.message);
        }

        try {
          AM.getRunningServices.overload("int").implementation = function (this: any, maxNum: any) {
            report("PROC", "ActivityManager.getRunningServices (running service enumeration)", "maxNum=" + maxNum);
            return this.getRunningServices(maxNum);
          };
        } catch (e: any) {
          log.warn("PROC", "ActivityManager.getRunningServices hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("PROC", "Could not hook android.app.ActivityManager: " + e.message);
      }

      // ---- IPC: ContextWrapper startActivity / sendBroadcast / registerReceiver ----
      try {
        const ContextWrapper = Java.use("android.content.ContextWrapper");

        function intentStr(intent: any): string {
          let s = "";
          try {
            if (intent !== null) {
              let act = "";
              try {
                act = "" + intent.getAction();
              } catch (e) {}
              let data = "";
              try {
                data = "" + intent.getDataString();
              } catch (e) {}
              let comp = "";
              try {
                const c = intent.getComponent();
                if (c !== null) comp = "" + c.flattenToString();
              } catch (e) {}
              s = "action=" + act + " data=" + data + (comp ? " comp=" + comp : "");
            }
          } catch (e) {}
          return s;
        }

        try {
          ContextWrapper.startActivity.overload("android.content.Intent").implementation = function (
            this: any,
            intent: any
          ) {
            report("IPC", "ContextWrapper.startActivity", intentStr(intent));
            return this.startActivity(intent);
          };
        } catch (e: any) {
          log.warn("IPC", "ContextWrapper.startActivity(Intent) hook unavailable: " + e.message);
        }

        try {
          ContextWrapper.startActivity
            .overload("android.content.Intent", "android.os.Bundle")
            .implementation = function (this: any, intent: any, opts: any) {
            report("IPC", "ContextWrapper.startActivity", intentStr(intent));
            return this.startActivity(intent, opts);
          };
        } catch (e: any) {
          log.warn("IPC", "ContextWrapper.startActivity(Intent,Bundle) hook unavailable: " + e.message);
        }

        try {
          ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function (
            this: any,
            intent: any
          ) {
            report("IPC", "ContextWrapper.sendBroadcast", intentStr(intent));
            return this.sendBroadcast(intent);
          };
        } catch (e: any) {
          log.warn("IPC", "ContextWrapper.sendBroadcast(Intent) hook unavailable: " + e.message);
        }

        try {
          ContextWrapper.sendBroadcast
            .overload("android.content.Intent", "java.lang.String")
            .implementation = function (this: any, intent: any, perm: any) {
            report("IPC", "ContextWrapper.sendBroadcast", intentStr(intent));
            return this.sendBroadcast(intent, perm);
          };
        } catch (e: any) {
          log.warn("IPC", "ContextWrapper.sendBroadcast(Intent,String) hook unavailable: " + e.message);
        }

        try {
          ContextWrapper.registerReceiver
            .overload("android.content.BroadcastReceiver", "android.content.IntentFilter")
            .implementation = function (this: any, rcv: any, filter: any) {
            let act = "";
            try {
              if (filter !== null && filter.countActions() > 0) act = "" + filter.getAction(0);
            } catch (e) {}
            report("IPC", "ContextWrapper.registerReceiver", "firstAction=" + act);
            return this.registerReceiver(rcv, filter);
          };
        } catch (e: any) {
          log.warn("IPC", "ContextWrapper.registerReceiver(2-arg) hook unavailable: " + e.message);
        }

        try {
          ContextWrapper.registerReceiver
            .overload(
              "android.content.BroadcastReceiver",
              "android.content.IntentFilter",
              "java.lang.String",
              "android.os.Handler"
            )
            .implementation = function (this: any, rcv: any, filter: any, perm: any, handler: any) {
            let act = "";
            try {
              if (filter !== null && filter.countActions() > 0) act = "" + filter.getAction(0);
            } catch (e) {}
            report("IPC", "ContextWrapper.registerReceiver", "firstAction=" + act);
            return this.registerReceiver(rcv, filter, perm, handler);
          };
        } catch (e: any) {
          log.warn("IPC", "ContextWrapper.registerReceiver(4-arg) hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("IPC", "Could not hook android.content.ContextWrapper: " + e.message);
      }

      // ---- Clipboard theft: ClipboardManager get/set PrimaryClip ----
      try {
        const Clipboard = Java.use("android.content.ClipboardManager");

        function clipStr(clip: any): string {
          // Clipboard content is attacker-controlled and may be large; bound how much we
          // materialize across the JNI bridge (each item is truncated, and we stop early once
          // the accumulator is large enough for triage).
          const CLIP_CAP = 512;
          let s = "";
          try {
            if (clip !== null) {
              const n = clip.getItemCount();
              for (let i = 0; i < n && s.length < CLIP_CAP; i++) {
                try {
                  const item = clip.getItemAt(i);
                  const t = item.getText();
                  if (t !== null) {
                    let chunk = "" + t;
                    if (chunk.length > CLIP_CAP) chunk = chunk.substring(0, CLIP_CAP);
                    s += (i ? " | " : "") + chunk;
                  }
                } catch (e) {}
              }
            }
          } catch (e) {}
          return s;
        }

        try {
          Clipboard.getPrimaryClip.overload().implementation = function (this: any) {
            const clip = this.getPrimaryClip();
            report("CLIP", "ClipboardManager.getPrimaryClip (clipboard read/theft)", clipStr(clip));
            return clip;
          };
        } catch (e: any) {
          log.warn("CLIP", "ClipboardManager.getPrimaryClip hook unavailable: " + e.message);
        }

        try {
          Clipboard.setPrimaryClip.overload("android.content.ClipData").implementation = function (
            this: any,
            clip: any
          ) {
            report("CLIP", "ClipboardManager.setPrimaryClip (clipboard write/hijack)", clipStr(clip));
            return this.setPrimaryClip(clip);
          };
        } catch (e: any) {
          log.warn("CLIP", "ClipboardManager.setPrimaryClip hook unavailable: " + e.message);
        }
      } catch (e: any) {
        log.warn("CLIP", "Could not hook android.content.ClipboardManager: " + e.message);
      }

      log.setup(
        TAG,
        "Hooked Behavioral IPC (SMS, A11Y, ContentResolver, exec, PackageManager, ActivityManager, IPC, Clipboard)"
      );
    });
  },
};

export default mod;
