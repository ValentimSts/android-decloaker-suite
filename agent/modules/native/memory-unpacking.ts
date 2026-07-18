// Ported from legacy decloaker.js hookMemoryUnpacking (lines 3580-3782), plus its
// module-private PROT_*/MAP_ANONYMOUS constants, protStr, and maybeDumpExecRegion
// helpers (lines 3554-3578).
//
// mprotect / mmap / mmap64 / memfd_create / munmap / remap_file_pages: the primitives
// a native unpacker uses to stage a decrypted payload in memory, flip it executable,
// and (sometimes) tear the evidence back down afterwards.

import { config } from "../../config";
import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { getExportSafe, readStrSafe, hexPreview, payloadMagic, dumpBuffer } from "../../core/memory";
import { getNativeBacktrace, formatBacktrace, isTargetCaller } from "../../core/backtrace";
import { scan } from "../../filters/matcher";
import type { IC, DecloakerModule } from "../../types";

const TAG = "MEM-UNPACK";

// PROT_* and MAP_* constants (Linux/Android, arm64 + x86_64 share these values).
const PROT_EXEC = 0x4;
const PROT_WRITE = 0x2;
const PROT_READ = 0x1;
const MAP_ANONYMOUS = 0x20; // MAP_ANON on Android/Linux

// Render a protection bitmask as "rwx" (dashes for missing bits) for readable logs.
function protStr(prot: number): string {
  return (
    (prot & PROT_READ ? "r" : "-") +
    (prot & PROT_WRITE ? "w" : "-") +
    (prot & PROT_EXEC ? "x" : "-")
  );
}

// Consider a dump when a region becomes executable and its magic looks like real code/archive.
// dumpBuffer() itself only writes to dumpDir when dumpPayloads is set; otherwise it just logs
// magic + size + preview, so this call is safe even when payload dumping is disabled.
function maybeDumpExecRegion(tag: string, addr: NativePointer, len: number): void {
  if (!addr || addr.isNull() || len <= 0) return;
  try {
    const magic = payloadMagic(addr);
    if (magic) {
      dumpBuffer(tag + ":" + magic, addr, len);
    }
  } catch (e) {}
}

const mod: DecloakerModule = {
  id: "memory-unpacking",
  tag: TAG,
  description:
    "Hooks mprotect/mmap/mmap64/memfd_create/munmap/remap_file_pages to catch in-memory unpacking",
  enabledByDefault: true,
  install() {
    if (!config.hookMemoryProtection) {
      log.info(TAG, "Memory hooks (mmap/mprotect/munmap) DISABLED (prevents JIT crash).");
    }

    // ---- mprotect --------------------------------------------------------
    // args: addr, len, prot. GATING: this is extremely hot, so we LOG ONLY when the requested
    // prot contains PROT_EXEC. We additionally read the region's CURRENT protection on enter to
    // detect a W->X transition (writable page flipped to executable = classic unpacker) and RWX,
    // the strongest unpacker signals. Non-exec mprotect (the common case) is dropped silently.
    const mprotectPtr = getExportSafe("libc.so", "mprotect");
    if (config.hookMemoryProtection && mprotectPtr) {
      Interceptor.attach(mprotectPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.prot = args[2].toInt32();
          // Content gate: ignore anything that does not request execute permission.
          if ((this.prot & PROT_EXEC) === 0) {
            this.skip = true;
            return;
          }
          this.skip = false;

          this.addr = args[0];
          // len is size_t: use toUInt32() so a large mapping does not truncate to a
          // negative int32 and silently defeat the len <= 0 guard in maybeDumpExecRegion.
          this.len = args[1].toUInt32();

          // Was the region writable BEFORE this call? If so, W->X transition.
          this.wasWritable = false;
          try {
            const range = Process.findRangeByAddress(this.addr);
            if (range && range.protection && range.protection.indexOf("w") !== -1) {
              this.wasWritable = true;
            }
          } catch (e) {}

          const isRWX =
            (this.prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ===
            (PROT_READ | PROT_WRITE | PROT_EXEC);

          const ctx = this.context;
          const bt = formatBacktrace(getNativeBacktrace(ctx));
          const sig = "mprotect|" + this.addr + "|" + this.prot;

          if (!hasSeen(sig)) {
            markSeen(sig);
            const label = isRWX
              ? "RWX region (unpacker)"
              : this.wasWritable
              ? "W->X transition (unpacker)"
              : "region made executable";
            const fields: Array<[string, string]> = [
              [
                "Region",
                "addr=" + this.addr + " len=" + this.len +
                  " prot=" + protStr(this.prot) + " (0x" + this.prot.toString(16) + ")",
              ],
            ];
            try {
              fields.push(["Preview", hexPreview(this.addr, 32)]);
            } catch (e) {}
            log.detect(TAG, "[mprotect] " + label, fields, bt);
          }
        },
        onLeave: function (this: IC, retval) {
          if (this.skip) return;
          // Only after the page is actually executable can we meaningfully sniff its magic.
          if (retval.toInt32() === 0) {
            maybeDumpExecRegion("mprotect-exec", this.addr, this.len);
          }
        },
      });
      log.setup(TAG, "Hooked Memory: mprotect (PROT_EXEC gated)");
    }

    // ---- mmap / mmap64 ---------------------------------------------------
    // args: addr, len, prot, flags, fd, offset. GATING: mmap is extremely hot, so we LOG ONLY
    // when prot contains PROT_EXEC (executable mapping) or is fully RWX. Ordinary file/anon data
    // mappings without execute are dropped. MAP_ANONYMOUS is noted (anon+exec = staged shellcode).
    for (const fn of ["mmap", "mmap64"] as const) {
      if (!config.hookMemoryProtection) continue;
      const mmapPtr = getExportSafe("libc.so", fn);
      if (!mmapPtr) continue;
      Interceptor.attach(mmapPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.prot = args[2].toInt32();
          if ((this.prot & PROT_EXEC) === 0) {
            this.skip = true;
            return;
          } // content gate
          this.skip = false;

          this.len = args[1].toUInt32(); // size_t: avoid negative int32 truncation
          this.flags = args[3].toInt32();
          this.ctx = this.context;
        },
        onLeave: function (this: IC, retval) {
          if (this.skip) return;
          // MAP_FAILED is (void*)-1; compare pointers directly (toInt32() would rely on a
          // 64-bit->int32 truncation of the all-ones pointer to happen to equal -1).
          if (retval.isNull() || retval.equals(ptr("-1"))) return;

          const isRWX =
            (this.prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ===
            (PROT_READ | PROT_WRITE | PROT_EXEC);
          const isAnon = (this.flags & MAP_ANONYMOUS) !== 0;

          const sig = "mmap|" + retval + "|" + this.prot + "|" + this.flags;
          if (!hasSeen(sig)) {
            markSeen(sig);
            let label = isRWX ? "RWX mapping (unpacker)" : "executable mapping";
            if (isAnon) label += " [MAP_ANONYMOUS - fileless]";
            const fields: Array<[string, string]> = [
              [
                "Region",
                "base=" + retval + " len=" + this.len +
                  " prot=" + protStr(this.prot) + " (0x" + this.prot.toString(16) + ")" +
                  " flags=0x" + this.flags.toString(16),
              ],
            ];
            try {
              fields.push(["Preview", hexPreview(retval, 32)]);
            } catch (e) {}
            log.detect(TAG, "[" + fn + "] " + label, fields, formatBacktrace(getNativeBacktrace(this.ctx)));
          }
          maybeDumpExecRegion(fn + "-exec", retval, this.len);
        },
      });
      log.setup(TAG, "Hooked Memory: " + fn + " (PROT_EXEC gated)");
    }

    // ---- memfd_create ----------------------------------------------------
    // arg0 = name. Fileless staging primitive: an anonymous in-memory file often used to stage a
    // decrypted dex/elf then execute it (memfd + mmap PROT_EXEC). Low frequency, so always log.
    const memfdPtr = getExportSafe("libc.so", "memfd_create");
    if (memfdPtr) {
      Interceptor.attach(memfdPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.skip = false;
          this.name = readStrSafe(args[0]);
          this.ctx = this.context;
        },
        onLeave: function (this: IC, retval) {
          if (this.skip) return;
          const sig = "memfd_create|" + this.name;
          if (!hasSeen(sig)) {
            markSeen(sig);
            log.detect(
              TAG,
              '[memfd_create] Fileless in-memory staging: name="' + this.name + '" -> fd=' + retval.toInt32(),
              undefined,
              formatBacktrace(getNativeBacktrace(this.ctx))
            );
          }
          // Feed the name through the lexicon (may hit dex/frida/etc. artifacts).
          // Capture ctx in a local: inside the trace closure `this` is NOT the Interceptor
          // context (scan invokes the callback bare).
          const ctx = this.ctx;
          scan("memfd_create", this.name, () => getNativeBacktrace(ctx));
        },
      });
      log.setup(TAG, "Hooked Memory: memfd_create");
    }

    // ---- munmap / remap_file_pages --------------------------------------
    // Anti-dump: unpackers often unmap or remap the region that held the decrypted payload right
    // after use so a later memory scrape finds nothing. Both are far lower frequency than mmap;
    // gated by isTargetCaller and deduped, so they cannot flood.
    const munmapPtr = getExportSafe("libc.so", "munmap");
    if (config.hookMemoryProtection && munmapPtr) {
      Interceptor.attach(munmapPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) return;
          const addr = args[0];
          const len = args[1].toUInt32(); // size_t
          // Only surface unmaps of currently-executable regions (payload teardown); a plain
          // data unmap is noise. If we cannot resolve the range, stay quiet.
          let isExec = false;
          try {
            const range = Process.findRangeByAddress(addr);
            isExec = !!(range && range.protection && range.protection.indexOf("x") !== -1);
          } catch (e) {}
          if (!isExec) return;

          const sig = "munmap|" + addr + "|" + len;
          if (!hasSeen(sig)) {
            markSeen(sig);
            const ctx = this.context;
            log.detect(
              TAG,
              "[munmap] Executable region unmapped (possible anti-dump): addr=" + addr + " len=" + len,
              undefined,
              formatBacktrace(getNativeBacktrace(ctx))
            );
          }
        },
      });
      log.setup(TAG, "Hooked Memory: munmap (exec regions only)");
    }

    const remapPtr = getExportSafe("libc.so", "remap_file_pages");
    if (config.hookMemoryProtection && remapPtr) {
      Interceptor.attach(remapPtr, {
        onEnter: function (this: IC, args) {
          if (!isTargetCaller(this.returnAddress)) return;
          const addr = args[0];
          const size = args[1].toUInt32(); // size_t
          const sig = "remap_file_pages|" + addr;
          if (!hasSeen(sig)) {
            markSeen(sig);
            const ctx = this.context;
            log.detect(
              TAG,
              "[remap_file_pages] Non-linear page remap (possible anti-dump): addr=" + addr + " size=" + size,
              undefined,
              formatBacktrace(getNativeBacktrace(ctx))
            );
          }
        },
      });
      log.setup(TAG, "Hooked Memory: remap_file_pages");
    }
  },
};

export default mod;
