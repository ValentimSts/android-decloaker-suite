// Ported from legacy decloaker.js hookNetworkC2Java (lines 4565-4984).
//
// Java-layer network endpoint discovery (URL/HttpURLConnection/WebView/OkHttp/
// DatagramSocket) plus TLS certificate-pinning observation. Pinning/trust
// NEUTRALIZATION only happens when config.activeBypass is true; otherwise every
// hook is observe-and-log only (no MITM enabled). Every observed value is also
// routed through scan() (legacy checkAndLog) for lexicon matching in addition to
// the explicit observation log line.

import { config } from "../../config";
import { log } from "../../core/logger";
import { scan } from "../../filters/matcher";
import { Java, withJava } from "../../core/java";
import type { DecloakerModule } from "../../types";

// Legacy embedded several inline tags: NET-C2 (endpoints), TLS-PIN (pinning/trust
// surfaces), and WS-INBOUND / WS-INBOUND-BINARY (OkHttp WebSocket frames). The RED
// [BYPASS] mark on neutralization lines is supplied by log.bypass. All preserved.
const TAG_NET_C2 = "NET-C2";
const TAG_TLS_PIN = "TLS-PIN";
const TAG_WS_INBOUND = "WS-INBOUND";
const TAG_WS_INBOUND_BINARY = "WS-INBOUND-BINARY";

const mod: DecloakerModule = {
  id: "net-c2-java",
  tag: TAG_NET_C2,
  description:
    "Hooks Java network C2 surfaces (URL/HttpURLConnection/WebView/OkHttp/DatagramSocket/WebSocket) and TLS pinning, with gated MITM bypass",
  enabledByDefault: true,
  requires: "java",
  install() {
    // Belt-and-suspenders: the dispatcher already gates this module on
    // Java.available via `requires: "java"`, but the legacy script warned and
    // returned here too, so we preserve that exact output.
    if (!Java.available) {
      log.warn(TAG_NET_C2, "Java is not available. Skipping Network C2 / pinning hooks.");
      return;
    }

    // Tri-state cache registered ONCE, lazily, the first time SSLContext.init is
    // neutralized under activeBypass: null = not yet tried, false = registration
    // failed, otherwise the registered wrapper. Java.registerClass twice with the
    // same name throws "class already exists"; caching the wrapper is what lets the
    // bypass survive more than a single TLS handshake.
    let permissiveTM: any = null;
    function getPermissiveTrustManager(): any {
      if (permissiveTM !== null) return permissiveTM;
      try {
        const X509TM = Java.use("javax.net.ssl.X509TrustManager");
        permissiveTM = Java.registerClass({
          name: "com.amas.decloak.PermissiveTrustManager",
          implements: [X509TM],
          methods: {
            checkClientTrusted: function (chain: any, authType: any) {},
            checkServerTrusted: function (chain: any, authType: any) {},
            // Return a plain empty JS array. Java.array("...X509Certificate", [])
            // cannot infer an element type from an empty list and throws on some
            // Frida versions.
            getAcceptedIssuers: function () {
              return [];
            },
          },
        });
      } catch (e) {
        permissiveTM = false;
      }
      return permissiveTM;
    }

    withJava(() => {
      // Local (non-shared) Java backtrace helper for the pure-Java call sites below.
      let logCls: any = null;
      let throwableCls: any = null;
      try {
        logCls = Java.use("android.util.Log");
        throwableCls = Java.use("java.lang.Throwable");
      } catch (e: any) {
        log.warn(TAG_NET_C2, "Java backtrace helpers unavailable: " + e.message);
      }
      function javaBacktrace(tag: string): string {
        try {
          if (!logCls || !throwableCls) return "";
          const t = throwableCls.$new(tag);
          const stack: string[] = logCls.getStackTraceString(t).split("\n");
          return stack.slice(1, 8).join("\n    ");
        } catch (e) {
          return "";
        }
      }

      // ---- java.net.URL.$init [full URL] ----------------------------------
      try {
        const URL = Java.use("java.net.URL");
        URL.$init.overload("java.lang.String").implementation = function (this: any, spec: any) {
          try {
            log.detect(TAG_NET_C2, "URL(): " + spec);
            scan("java.net.URL", "" + spec);
          } catch (e) {}
          return this.$init(spec);
        };
      } catch (e: any) {
        log.warn(TAG_NET_C2, "Could not hook java.net.URL.$init: " + e.message);
      }

      // ---- HttpURLConnectionImpl: setRequestMethod / getInputStream -------
      try {
        const HUC = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");
        try {
          HUC.setRequestMethod.overload("java.lang.String").implementation = function (
            this: any,
            method: any
          ) {
            try {
              let url = "";
              try {
                url = "" + this.getURL();
              } catch (e2) {}
              log.detect(TAG_NET_C2, "HttpURLConnection.setRequestMethod: " + method + " " + url);
              scan("HttpURLConnection.method", method + " " + url);
            } catch (e) {}
            return this.setRequestMethod(method);
          };
        } catch (e: any) {
          log.warn(TAG_NET_C2, "Could not hook HttpURLConnectionImpl.setRequestMethod: " + e.message);
        }
        try {
          HUC.getInputStream.overload().implementation = function (this: any) {
            try {
              let url = "";
              try {
                url = "" + this.getURL();
              } catch (e2) {}
              let method = "";
              try {
                method = "" + this.getRequestMethod();
              } catch (e3) {}
              let headers = "";
              try {
                headers = "" + this.getRequestProperties();
              } catch (e4) {}
              log.detect(
                TAG_NET_C2,
                "HttpURLConnection.getInputStream: " + method + " " + url,
                headers ? [["Headers", headers]] : undefined
              );
              scan("HttpURLConnection.request", method + " " + url + " " + headers);
            } catch (e) {}
            return this.getInputStream();
          };
        } catch (e: any) {
          log.warn(TAG_NET_C2, "Could not hook HttpURLConnectionImpl.getInputStream: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG_NET_C2, "HttpURLConnectionImpl not present (skipping): " + e.message);
      }

      // ---- android.webkit.WebView: loadUrl / postUrl / evaluateJavascript -
      try {
        const WebView = Java.use("android.webkit.WebView");
        try {
          WebView.loadUrl.overload("java.lang.String").implementation = function (this: any, url: any) {
            try {
              log.detect(TAG_NET_C2, "WebView.loadUrl: " + url);
              scan("WebView.loadUrl", "" + url);
            } catch (e) {}
            return this.loadUrl(url);
          };
        } catch (e: any) {
          log.warn(TAG_NET_C2, "Could not hook WebView.loadUrl(String): " + e.message);
        }
        try {
          WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (
            this: any,
            url: any,
            headers: any
          ) {
            try {
              log.detect(
                TAG_NET_C2,
                "WebView.loadUrl (with headers): " + url,
                headers ? [["Headers", "" + headers]] : undefined
              );
              scan("WebView.loadUrl", "" + url + " " + headers);
            } catch (e) {}
            return this.loadUrl(url, headers);
          };
        } catch (e: any) {
          log.warn(TAG_NET_C2, "Could not hook WebView.loadUrl(String,Map): " + e.message);
        }
        try {
          WebView.postUrl.overload("java.lang.String", "[B").implementation = function (
            this: any,
            url: any,
            data: any
          ) {
            try {
              const len = data ? data.length : 0;
              log.detect(TAG_NET_C2, "WebView.postUrl: " + url + " (postData " + len + " bytes)");
              scan("WebView.postUrl", "" + url);
            } catch (e) {}
            return this.postUrl(url, data);
          };
        } catch (e: any) {
          log.warn(TAG_NET_C2, "Could not hook WebView.postUrl: " + e.message);
        }
        try {
          WebView.evaluateJavascript.overload(
            "java.lang.String",
            "android.webkit.ValueCallback"
          ).implementation = function (this: any, script: any, cb: any) {
            try {
              let preview = "" + script;
              if (preview.length > 300) preview = preview.substring(0, 300) + "...[TRUNCATED]";
              log.dump(TAG_NET_C2, "WebView.evaluateJavascript: " + preview);
              scan("WebView.evaluateJavascript", "" + script);
            } catch (e) {}
            return this.evaluateJavascript(script, cb);
          };
        } catch (e: any) {
          log.warn(TAG_NET_C2, "Could not hook WebView.evaluateJavascript: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG_NET_C2, "android.webkit.WebView not present (skipping): " + e.message);
      }

      // ---- okhttp3.Request$Builder.url / build ---------------------------
      try {
        const ReqBuilder = Java.use("okhttp3.Request$Builder");
        try {
          ReqBuilder.url.overload("java.lang.String").implementation = function (this: any, url: any) {
            try {
              log.detect(TAG_NET_C2, "okhttp3.Request.Builder.url: " + url);
              scan("okhttp3.Request.url", "" + url);
            } catch (e) {}
            return this.url(url);
          };
        } catch (e) {
          log.warn(TAG_NET_C2, "Could not hook okhttp3.Request$Builder.url(String): ");
        }
        try {
          ReqBuilder.build.overload().implementation = function (this: any) {
            const req = this.build();
            try {
              let url = "",
                method = "",
                headers = "";
              try {
                url = "" + req.url();
              } catch (e2) {}
              try {
                method = "" + req.method();
              } catch (e3) {}
              try {
                headers = "" + req.headers();
              } catch (e4) {}
              log.detect(
                TAG_NET_C2,
                "okhttp3.Request.build: " + method + " " + url,
                headers ? [["Headers", headers]] : undefined
              );
              scan("okhttp3.Request.build", method + " " + url + " " + headers);
            } catch (e) {}
            return req;
          };
        } catch (e) {
          log.warn(TAG_NET_C2, "Could not hook okhttp3.Request$Builder.build: ");
        }
      } catch (e) {
        log.warn(TAG_NET_C2, "okhttp3.Request$Builder not present (skipping): ");
      }

      // ---- okhttp3.CertificatePinner.check -------------------------------
      // Observe pinned host always. Under activeBypass only, no-op (return) so the
      // pin never fails and a MITM proxy's cert is accepted. Returns void -> bare
      // `return;` is correct.
      try {
        const CertPinner = Java.use("okhttp3.CertificatePinner");
        // The public overloads are check(String, List) and the varargs
        // check(String, Certificate...) whose JVM type is
        // [Ljava.security.cert.Certificate;. There is NO check(String, String).
        ["java.util.List", "[Ljava.security.cert.Certificate;"].forEach(function (listType) {
          try {
            CertPinner.check.overload("java.lang.String", listType).implementation = function (
              this: any,
              hostname: any,
              peerCerts: any
            ) {
              try {
                log.detect(TAG_TLS_PIN, "okhttp3.CertificatePinner.check host: " + hostname);
                scan("CertificatePinner.check", "" + hostname);
              } catch (e) {}
              if (config.activeBypass) {
                log.bypass(TAG_TLS_PIN, "Neutralizing okhttp CertificatePinner.check (allowing MITM).");
                return;
              }
              return this.check(hostname, peerCerts);
            };
          } catch (e: any) {
            log.warn(TAG_TLS_PIN, "Could not hook CertificatePinner.check(" + listType + "): " + e.message);
          }
        });
      } catch (e) {
        log.warn(TAG_TLS_PIN, "okhttp3.CertificatePinner not present (skipping): ");
      }

      // ---- Conscrypt TrustManagerImpl(s): checkServerTrusted(chain,authType) ----
      // Hook concrete framework impls (the interface has no overridable body).
      // Observe the leaf; under activeBypass return without throwing so the chain
      // is accepted.
      [
        "com.android.org.conscrypt.TrustManagerImpl",
        "com.google.android.gms.org.conscrypt.TrustManagerImpl",
      ].forEach(function (tmCls) {
        try {
          const TMI = Java.use(tmCls);
          try {
            TMI.checkServerTrusted.overload(
              "[Ljava.security.cert.X509Certificate;",
              "java.lang.String"
            ).implementation = function (this: any, chain: any, authType: any) {
              try {
                const leaf = chain && chain.length > 0 ? "" + chain[0].getSubjectDN() : "?";
                log.detect(
                  TAG_TLS_PIN,
                  tmCls + ".checkServerTrusted authType=" + authType + " leaf=" + leaf
                );
                scan(tmCls + ".checkServerTrusted", leaf);
              } catch (e) {}
              if (config.activeBypass) {
                log.bypass(TAG_TLS_PIN, "Accepting server chain without validation (allowing MITM).");
                return;
              }
              return this.checkServerTrusted(chain, authType);
            };
          } catch (e: any) {
            log.warn(
              TAG_TLS_PIN,
              "Could not hook " + tmCls + ".checkServerTrusted(chain,authType): " + e.message
            );
          }
        } catch (e) {
          log.warn(TAG_TLS_PIN, "TrustManager impl not present (" + tmCls + "): ");
        }
      });

      // ---- com.android.org.conscrypt.TrustManagerImpl.verifyChain / checkTrusted ----
      // These return List<X509Certificate>. Under activeBypass, short-circuit by
      // returning the presented chain as a List so pinning/validation is bypassed.
      // Overloads vary by API level, so each is guarded; the ArrayList/List uses are
      // try/caught so a runtime failure in the .implementation body never propagates
      // into the app.
      try {
        const Conscrypt = Java.use("com.android.org.conscrypt.TrustManagerImpl");

        // verifyChain/checkTrusted signatures vary widely across API levels and
        // Conscrypt builds (arg0 is sometimes X509Certificate[], sometimes List;
        // extra ocsp/sct/session/params args come and go), so hook ALL overloads
        // generically rather than hardcoding one signature that may not exist on
        // this device.

        // Return the presented chain as a java.util.List (cast if already a List,
        // else build one).
        function chainToList(chain: any): any {
          const ListCls = Java.use("java.util.List");
          try {
            return Java.cast(chain, ListCls);
          } catch (e) {}
          const ArrayListCls = Java.use("java.util.ArrayList");
          const out = ArrayListCls.$new();
          try {
            for (let i = 0; i < chain.length; i++) out.add(chain[i]);
          } catch (e) {}
          return Java.cast(out, ListCls);
        }
        function firstStringArg(a: any): string {
          for (let i = 0; i < a.length; i++) {
            if (typeof a[i] === "string") return a[i];
          }
          return "";
        }

        ["verifyChain", "checkTrusted"].forEach(function (method) {
          try {
            if (!Conscrypt[method]) return;
            Conscrypt[method].overloads.forEach(function (ov: any) {
              // Classic function (never arrow): closes over `arguments` and rebinds
              // `this` per call so ov.apply(this, arguments) chains to the original.
              ov.implementation = function (this: any) {
                const host = firstStringArg(arguments);
                try {
                  log.detect(TAG_TLS_PIN, "Conscrypt." + method + " host/authType=" + host);
                  scan("Conscrypt." + method, "" + host);
                } catch (e) {}
                if (config.activeBypass) {
                  try {
                    let rt = "";
                    try {
                      rt = ov.returnType.className;
                    } catch (e) {}
                    log.bypass(TAG_TLS_PIN, "Neutralizing Conscrypt." + method + " (pinning bypass).");
                    // void validators: returning nothing == accept. Chain-returning
                    // validators: hand back the presented chain as trusted.
                    if (rt === "void") return;
                    return chainToList(arguments[0]);
                  } catch (e2: any) {
                    log.warn(
                      TAG_TLS_PIN,
                      "[BYPASS] " + method + " fallback (running original): " + e2.message
                    );
                  }
                }
                return ov.apply(this, arguments);
              };
            });
            log.setup(TAG_TLS_PIN, "Hooked Conscrypt." + method + " (all overloads)");
          } catch (e: any) {
            log.warn(TAG_TLS_PIN, "Could not hook Conscrypt." + method + ": " + e.message);
          }
        });
      } catch (e: any) {
        log.warn(TAG_TLS_PIN, "com.android.org.conscrypt.TrustManagerImpl not present: " + e.message);
      }

      // ---- javax.net.ssl.SSLContext.init ---------------------------------
      // Observe custom TrustManager arrays being installed. Under activeBypass,
      // replace the supplied array with a single all-trusting X509TrustManager
      // (registered once) so any server cert is accepted.
      try {
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
          "[Ljavax.net.ssl.KeyManager;",
          "[Ljavax.net.ssl.TrustManager;",
          "java.security.SecureRandom"
        ).implementation = function (this: any, km: any, tm: any, sr: any) {
          try {
            const tmCount = tm ? tm.length : 0;
            const bt = javaBacktrace("SSLContextInit");
            log.detect(
              TAG_TLS_PIN,
              "SSLContext.init with " + tmCount + " TrustManager(s).",
              bt ? [["Java Backtrace", bt]] : undefined
            );
          } catch (e) {}
          if (config.activeBypass) {
            try {
              const TM = getPermissiveTrustManager();
              if (TM) {
                log.bypass(
                  TAG_TLS_PIN,
                  "Installing all-trusting X509TrustManager into SSLContext (allowing MITM)."
                );
                const tmArr = Java.array("javax.net.ssl.TrustManager", [TM.$new()]);
                return this.init(km, tmArr, sr);
              }
              log.warn(TAG_TLS_PIN, "[BYPASS] Permissive TrustManager unavailable; passing original TrustManagers.");
            } catch (e: any) {
              log.warn(TAG_TLS_PIN, "[BYPASS] Failed to install permissive TrustManager: " + e.message);
            }
          }
          return this.init(km, tm, sr);
        };
      } catch (e: any) {
        log.warn(TAG_TLS_PIN, "Could not hook SSLContext.init: " + e.message);
      }

      // ---- java.net.DatagramSocket.send [UDP dest + payload] -------------
      try {
        const DatagramSocket = Java.use("java.net.DatagramSocket");
        DatagramSocket.send.overload("java.net.DatagramPacket").implementation = function (
          this: any,
          packet: any
        ) {
          try {
            let dest = "?";
            try {
              const addr = packet.getAddress();
              const host = addr ? "" + addr.getHostAddress() : "?";
              dest = host + ":" + packet.getPort();
            } catch (e2) {}
            let len = 0;
            try {
              len = packet.getLength();
            } catch (e3) {}

            // Bounded printable preview of the UDP payload for lexicon matching.
            // Frida byte[] elements are signed (-128..127); `& 0xff` normalizes to
            // 0..255 and getOffset() is honored so a packet built on a subrange is
            // read correctly.
            let payloadStr = "";
            try {
              const data = packet.getData();
              const off = packet.getOffset();
              const cap = len < 512 ? len : 512;
              const chars: number[] = [];
              for (let i = 0; i < cap; i++) {
                const b = data[off + i] & 0xff;
                if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) chars.push(b);
              }
              payloadStr = String.fromCharCode.apply(null, chars);
            } catch (e4) {}

            log.detect(
              TAG_NET_C2,
              "DatagramSocket.send (UDP) -> " + dest + " (" + len + " bytes)",
              payloadStr ? [["Payload preview", payloadStr]] : undefined
            );
            scan("DatagramSocket.send", dest + " " + payloadStr);
          } catch (e) {}
          return this.send(packet);
        };
      } catch (e: any) {
        log.warn(TAG_NET_C2, "Could not hook java.net.DatagramSocket.send: " + e.message);
      }

      // ---- Hook WebSocket Traffic via OkHttp Listener ----
      try {
        const WS = Java.use("okhttp3.WebSocketListener");

        // Hook String messages (most common for C2)
        WS.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function (
          this: any,
          ws: any,
          text: any
        ) {
          log.detect(TAG_WS_INBOUND, "" + text);
          scan("WebSocket.onMessage", text);
          return this.onMessage(ws, text);
        };

        // Hook ByteString messages (binary C2)
        WS.onMessage.overload("okhttp3.WebSocket", "okio.ByteString").implementation = function (
          this: any,
          ws: any,
          bytes: any
        ) {
          const hex = bytes.hex();
          log.detect(TAG_WS_INBOUND_BINARY, hex.substring(0, 64) + "...");
          return this.onMessage(ws, bytes);
        };
      } catch (e) {
        log.warn(TAG_WS_INBOUND, "Could not hook OkHttp WebSocketListener: ");
      }

      log.setup(
        TAG_NET_C2,
        "Hooked Java Network C2 & TLS-pinning surfaces (URL/HttpURLConnection/WebView/OkHttp/TrustManager/SSLContext/DatagramSocket)"
      );
    });
  },
};

export default mod;
