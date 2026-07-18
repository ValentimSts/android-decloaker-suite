// Ported from legacy decloaker.js hookNetworkTraffic, processNetworkBuffer,
// detectJSON, and readPrintableString (lines 652-782).
//
// Native module (no Java bridge). Hooks BoringSSL SSL_write/SSL_read (libssl.so
// and libjavacrypto.so, which ships its own copy on some OEM images) plus raw
// libc socket I/O (send/sendto/recv/recvfrom) to inspect plaintext buffers -
// before TLS encrypts them on write, after TLS decrypts them on read - for JSON
// payloads or target-lexicon string matches.

import { config } from "../config";
import { log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { getExportSafe, hexPreview } from "../core/memory";
import { getNativeBacktrace, formatBacktrace, isTargetCaller } from "../core/backtrace";
import { scan } from "../filters/matcher";
import type { IC, DecloakerModule } from "../types";

// Legacy embedded two distinct log tags: NETWORK (JSON payloads and the string
// scan) and RAW-NET (binary/non-JSON frame hex dumps). Both preserved here.
const TAG_NETWORK = "NETWORK";
const TAG_RAW_NET = "RAW-NET";

// Cap how many bytes we ever scan from a single network buffer. Bounds both the
// string-build cost and the downstream JSON matching (buffers can be up to ~1MB),
// neutralizing the DoS/ReDoS.
const NET_SCAN_CAP = 65536;

// Safely extract printable ASCII (plus \n \r \t) characters from a raw memory buffer.
function readPrintableString(p: NativePointer, size: number): string | null {
  if (p.isNull() || size <= 0) return null;
  try {
    const scanLen = size < NET_SCAN_CAP ? size : NET_SCAN_CAP;
    const bytes = new Uint8Array(p.readByteArray(scanLen) as ArrayBuffer);
    const chars: number[] = [];
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) {
        chars.push(b);
      }
    }
    // Build in bounded chunks; per-char string concatenation on large buffers is very slow.
    let str = "";
    for (let j = 0; j < chars.length; j += 8192) {
      str += String.fromCharCode.apply(null, chars.slice(j, j + 8192));
    }
    return str;
  } catch (e) {
    return null;
  }
}

// Heuristic detector for a JSON payload embedded in a printable string.
function detectJSON(str: string | null): string | null {
  if (!str) return null;
  // Bound the input and use non-backtracking character classes ([^{}] instead of greedy .*)
  // so a quote-heavy non-JSON buffer cannot trigger catastrophic backtracking (ReDoS).
  let bounded = str;
  if (bounded.length > NET_SCAN_CAP) bounded = bounded.substring(0, NET_SCAN_CAP);
  const match = bounded.match(/(\{[^{}]*"[\w]+"\s*:\s*[^{}]*\}|\[\s*\{[^{}]*\}\s*\])/s);
  if (match) {
    try {
      JSON.parse(match[0]);
      return match[0];
    } catch (e) {
      if (match[0].indexOf('":') !== -1) return match[0];
    }
  }
  return null;
}

function processNetworkBuffer(
  funcName: string,
  bufferPtr: NativePointer,
  size: number,
  context: CpuContext
): void {
  const rawStr = readPrintableString(bufferPtr, size);
  if (!rawStr) return;

  const jsonPayload = detectJSON(rawStr);

  if (jsonPayload) {
    const signature = funcName + "|" + jsonPayload.substring(0, 200);
    if (!hasSeen(signature)) {
      markSeen(signature);

      let display = jsonPayload;
      try {
        display = JSON.stringify(JSON.parse(jsonPayload), null, 2);
      } catch (e) {
        // Matched heuristically but doesn't parse on its own (e.g. truncated by
        // NET_SCAN_CAP) - fall back to the raw matched text.
      }

      // Backtrace only rendered when config.fullBacktrace is on (read at call time).
      log.detect(
        TAG_NETWORK,
        "Intercepted JSON Payload via: " + funcName,
        [["Payload", display]],
        config.fullBacktrace ? formatBacktrace(getNativeBacktrace(context)) : undefined
      );
    }
  } else if (size > 0) {
    // Likely a binary WebSocket frame or a non-JSON protocol. Legacy printed this
    // in PURPLE (a payload dump) and never deduped it, so every raw frame gets its
    // own hex preview.
    log.dump(TAG_RAW_NET, funcName + " (" + size + " bytes)", [
      ["Hex", hexPreview(bufferPtr, 128)],
    ]);
  } else {
    // Lazy backtrace thunk (never references `this`) - captures the copied context.
    scan("NETWORK: " + funcName, rawStr, () => getNativeBacktrace(context));
  }
}

interface NetHookConfig {
  mod: string;
  func: string;
  bufIdx: number;
  sizeIdx: number;
  isEnter: boolean;
}

const mod: DecloakerModule = {
  id: "network-traffic",
  tag: TAG_NETWORK,
  description: "Hooks SSL/socket I/O to inspect plaintext buffers for JSON payloads or target strings",
  enabledByDefault: true,
  install() {
    const networkFuncs: NetHookConfig[] = [
      // 1. Android/BoringSSL TLS
      { mod: "libssl.so", func: "SSL_write", bufIdx: 1, sizeIdx: 2, isEnter: true },
      { mod: "libssl.so", func: "SSL_read", bufIdx: 1, sizeIdx: 2, isEnter: false },
      { mod: "libjavacrypto.so", func: "SSL_write", bufIdx: 1, sizeIdx: 2, isEnter: true },
      { mod: "libjavacrypto.so", func: "SSL_read", bufIdx: 1, sizeIdx: 2, isEnter: false },

      // 2. Standard Libc Sockets
      { mod: "libc.so", func: "send", bufIdx: 1, sizeIdx: 2, isEnter: true },
      { mod: "libc.so", func: "sendto", bufIdx: 1, sizeIdx: 2, isEnter: true },
      { mod: "libc.so", func: "recv", bufIdx: 1, sizeIdx: 2, isEnter: false },
      { mod: "libc.so", func: "recvfrom", bufIdx: 1, sizeIdx: 2, isEnter: false },
    ];

    // `for...of` gives every Interceptor closure below its own per-iteration
    // `cfg` binding. A shared outer binding here would let every hook run with
    // the LAST cfg - silently breaking outbound (SSL_write/send) inspection and
    // mislabeling every alert.
    for (const cfg of networkFuncs) {
      const ptrAddress = getExportSafe(cfg.mod, cfg.func);
      if (!ptrAddress) continue;

      Interceptor.attach(ptrAddress, {
        // onEnter/onLeave share state via `this` (this.skip/bufPtr/size/ctx), so
        // both MUST stay classic functions to get a fresh InvocationContext per call.
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.skip = false;

          this.bufPtr = args[cfg.bufIdx];
          this.size = args[cfg.sizeIdx].toInt32();
          this.ctx = this.context;

          if (cfg.isEnter && this.size > 0 && this.size < 1048576) {
            processNetworkBuffer(cfg.func, this.bufPtr, this.size, this.ctx);
          }
        },
        onLeave: function (this: IC, retval) {
          if (this.skip) return;

          const bytesRead = retval.toInt32();
          if (!cfg.isEnter && bytesRead > 0 && bytesRead < 1048576) {
            processNetworkBuffer(cfg.func, this.bufPtr, bytesRead, this.ctx);
          }
        },
      });
      log.setup(TAG_NETWORK, "Hooked Network IO: " + cfg.func + " (" + cfg.mod + ")");
    }
  },
};

export default mod;
