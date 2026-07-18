// Ported from legacy decloaker.js hookNetworkC2Native, plus its module-private
// parseSockaddrC2 and compactIPv6 helpers (lines 4398-4564).
//
// C2 destination + DNS resolution hooks. NOTE ON GATING: unlike the hot file/syscall
// hooks in this agent, these are deliberately NOT gated by isTargetCaller - every
// socket destination and every resolved hostname is intelligence worth capturing
// regardless of the calling module. Flooding is instead controlled by dedup: connect()
// dedups on "ip:port", DNS hooks dedup on the hostname, so repeated dials/lookups to
// the same endpoint print once. connect() is a per-socket call (not a per-byte hot
// path like read/recv), so per-endpoint dedup is sufficient to prevent flooding.

import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { getExportSafe, readStrSafe } from "../../core/memory";
import { getNativeBacktrace, formatBacktrace } from "../../core/backtrace";
import { scan } from "../../filters/matcher";
import type { IC, DecloakerModule } from "../../types";

// Legacy embedded two distinct log tags inline: C2 CONNECT (the outbound socket
// destination) and DNS (resolved hostnames). Both preserved here.
const TAG_C2 = "C2 CONNECT";
const TAG_DNS = "DNS";

// Compact eight 16-bit groups into RFC 5952 form: lowercase hex, drop leading zeros,
// collapse the single longest run (length >= 2) of zero groups to "::".
function compactIPv6(groups: number[]): string {
  // Locate the longest zero-run.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  const parts: string[] = [];
  for (let j = 0; j < groups.length; j++) {
    parts.push(groups[j].toString(16));
  }

  if (bestLen >= 2) {
    const head = parts.slice(0, bestStart).join(":");
    const tail = parts.slice(bestStart + bestLen).join(":");
    return head + "::" + tail;
  }
  return parts.join(":");
}

// Parse a struct sockaddr* into a compact "ip:port" (or null for families we skip).
// Layout (Android/Linux): sa_family_t is a 2-byte host-order field at +0 (readU16 is
// correct on little-endian Android). AF_INET(2): port is network-order u16 at +2, IPv4
// 4 bytes at +4. AF_INET6(10): port network-order u16 at +2, then 4-byte flowinfo, then
// IPv6 16 bytes at +8. AF_UNIX(1) / AF_NETLINK(16) are local/kernel transports, not C2 -
// returned as null.
function parseSockaddrC2(addrPtr: NativePointer): string | null {
  try {
    if (addrPtr == null || addrPtr.isNull()) return null;

    const family = addrPtr.readU16();

    if (family === 2) {
      // AF_INET
      // Port is network byte order (big-endian): combine the two bytes hi:lo.
      const pHi = addrPtr.add(2).readU8();
      const pLo = addrPtr.add(3).readU8();
      const port = ((pHi << 8) | pLo) & 0xffff;

      const b0 = addrPtr.add(4).readU8();
      const b1 = addrPtr.add(5).readU8();
      const b2 = addrPtr.add(6).readU8();
      const b3 = addrPtr.add(7).readU8();
      const ip = b0 + "." + b1 + "." + b2 + "." + b3;
      return ip + ":" + port;
    }

    if (family === 10) {
      // AF_INET6
      const p6Hi = addrPtr.add(2).readU8();
      const p6Lo = addrPtr.add(3).readU8();
      const port6 = ((p6Hi << 8) | p6Lo) & 0xffff;

      // 16 address bytes (at +8, after 4-byte flowinfo) as eight big-endian 16-bit
      // groups, then RFC 5952 :: compaction.
      const groups: number[] = [];
      for (let i = 0; i < 8; i++) {
        const hi = addrPtr.add(8 + i * 2).readU8();
        const lo = addrPtr.add(8 + i * 2 + 1).readU8();
        groups.push(((hi << 8) | lo) & 0xffff);
      }
      const ip6 = compactIPv6(groups);
      // Bracket the host so ip6:port stays unambiguous (e.g. [::1]:443).
      return "[" + ip6 + "]:" + port6;
    }

    // Any other family (AF_UNIX=1, AF_NETLINK=16, etc.) is not a C2 endpoint.
    return null;
  } catch (e) {
    return null;
  }
}

interface DnsHookConfig {
  mod: string;
  func: string;
}

const mod: DecloakerModule = {
  id: "net-c2-native",
  tag: TAG_C2,
  description: "Hooks libc connect() and DNS resolvers to capture outbound socket destinations and resolved hostnames",
  enabledByDefault: true,
  install() {
    // --- libc connect(): the destination of every outbound socket (CRITICAL) ---
    // Signature: int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    // addr = args[1]. No isTargetCaller gate (see module note above).
    const connectPtr = getExportSafe("libc.so", "connect");
    if (connectPtr) {
      Interceptor.attach(connectPtr, {
        onEnter: function (this: IC, args) {
          const endpoint = parseSockaddrC2(args[1]);
          if (!endpoint) return; // AF_UNIX/AF_NETLINK/unknown -> skipped

          const signature = "connect|" + endpoint;
          if (hasSeen(signature)) return;
          markSeen(signature);

          // Capture the CpuContext into a local. The trace closure below must NOT
          // reference `this` - scan() invokes it as a bare function, so `this` would
          // not be the Interceptor context there. Compute the backtrace once and
          // reuse it for both the log line and scan() on this critical hook.
          const ctx = this.context;
          const bt = getNativeBacktrace(ctx);

          log.detect(
            TAG_C2,
            "Outbound socket destination: " + endpoint,
            undefined,
            formatBacktrace(bt)
          );

          // Also run the endpoint through the lexicon (matches known C2/IP-echo hosts if
          // the literal IP/port ever appears in TARGET_STRINGS). scan() dedups independently.
          scan("connect", endpoint, () => bt);
        },
      });
      log.setup(TAG_C2, "Hooked C2 Endpoint: connect (libc.so)");
    }

    // --- DNS resolution: hostname is the first string argument for each of these ---
    // getaddrinfo(const char *node, ...)                  -> node = args[0]
    // android_getaddrinfofornet(const char *hostname,...) -> hostname = args[0]
    // gethostbyname(const char *name)                     -> name = args[0]
    const dnsFuncs: DnsHookConfig[] = [
      { mod: "libc.so", func: "getaddrinfo" },
      { mod: "libc.so", func: "android_getaddrinfofornet" },
      { mod: "libc.so", func: "gethostbyname" },
    ];

    // `for...of` gives every Interceptor closure below its own per-iteration `cfg`
    // binding (mirrors network-traffic's loop) - a shared/outer binding would let every
    // hook run with the LAST cfg, silently mislabeling every alert.
    for (const cfg of dnsFuncs) {
      const dnsPtr = getExportSafe(cfg.mod, cfg.func);
      if (!dnsPtr) continue;

      Interceptor.attach(dnsPtr, {
        onEnter: function (this: IC, args) {
          // No isTargetCaller gate: every resolved hostname is worth logging.
          const host = readStrSafe(args[0]);
          if (!host) return;

          const signature = "dns|" + cfg.func + "|" + host;
          if (hasSeen(signature)) return;
          markSeen(signature);

          // Capture context locally; the trace closure must not reference `this`.
          const ctx = this.context;
          const bt = getNativeBacktrace(ctx);

          log.detect(
            TAG_DNS,
            cfg.func + " resolving host: " + host,
            undefined,
            formatBacktrace(bt)
          );

          // Match the resolved domain against the C2/evasion lexicon.
          scan(cfg.func, host, () => bt);
        },
      });
      log.setup(TAG_DNS, "Hooked DNS: " + cfg.func + " (" + cfg.mod + ")");
    }
  },
};

export default mod;
