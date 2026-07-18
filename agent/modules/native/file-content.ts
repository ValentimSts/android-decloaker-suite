// Ported from legacy decloaker.js hookFileContent (lines 2066-2461), plus its
// module-private FC_* state and fc* helpers (lines 2083-2208).
//
// THE biggest gap: nothing else inspects the BYTES a file read returns. Path hooks
// elsewhere fire on open("/proc/self/status") but never see the "TracerPid: 1234"
// that comes back. This module maintains fd->path and FILE*->path maps (populated by our
// OWN detection-only open/openat/fopen return-value hooks, cleared on close/fclose) and then
// inspects the read-back / write buffers, but ONLY when the associated path is "interesting"
// (starts with /proc/ or matches TARGET_REGEX). That single gate is what keeps these
// EXTREMELY hot functions (read/pread64/write/fread/...) from flooding on normal app I/O:
// a buffer is scanned only after we have already confirmed its backing path is suspicious.
//
// Catches: TracerPid in /proc/self/status, frida/gum in /proc/self/maps, magisk in
// /proc/mounts, port 27042 in /proc/net/tcp, and DEX/ELF/ZIP magic in dropped payloads.

import { getExportSafe, readStrSafe, payloadMagic, dumpBuffer } from "../../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../../core/backtrace";
import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { scan } from "../../filters/matcher";
import { TARGET_REGEX } from "../../filters/lexicon";
import type { IC, DecloakerModule } from "../../types";

const TAG = "FILE-CONTENT";

// fd (int) -> path string. Only "interesting" paths are ever recorded, so a present key
// already means "worth inspecting" - no re-check of the path is needed on the read side.
let FC_FD_PATHS: Record<number, string> = {};
// FILE* (pointer as string) -> path string, same "interesting only" invariant.
let FC_FILE_PATHS: Record<string, string> = {};

// Hard cap on how many entries the maps may hold. Long-running samples can churn millions
// of fds; without this the maps would grow unbounded. On overflow we drop the whole map
// (correctness is unaffected: a missing entry just means "don't inspect", never a false alert).
const FC_MAP_CAP = 4096;
let FC_FD_COUNT = 0;
let FC_FILE_COUNT = 0;

// Never scan more than 4096 bytes of any single buffer (per the spec) - bounds both the
// readByteArray cost and the downstream scan() regex work on large reads.
const FC_SCAN_CAP = 4096;

// A path is worth tracking iff it is a /proc/ pseudo-file (TracerPid/maps/mounts/net/tcp)
// or it hits the evasion lexicon. This is the ONLY admission gate into the maps, and hence
// the only content that can ever reach the read-back inspection below.
function fcPathInteresting(path: string): boolean {
  if (!path) return false;
  if (path.lastIndexOf("/proc/", 0) === 0) return true; // startsWith("/proc/")
  return TARGET_REGEX.test(path);
}

function fcRecordFd(fd: number, path: string): void {
  if (fd < 0 || !fcPathInteresting(path)) return;
  if (FC_FD_COUNT >= FC_MAP_CAP) {
    FC_FD_PATHS = {};
    FC_FD_COUNT = 0;
  }
  if (FC_FD_PATHS[fd] === undefined) FC_FD_COUNT++;
  FC_FD_PATHS[fd] = path;
}

function fcRecordFile(filePtr: NativePointer, path: string): void {
  if (!filePtr || filePtr.isNull() || !fcPathInteresting(path)) return;
  const key = filePtr.toString();
  if (FC_FILE_COUNT >= FC_MAP_CAP) {
    FC_FILE_PATHS = {};
    FC_FILE_COUNT = 0;
  }
  if (FC_FILE_PATHS[key] === undefined) FC_FILE_COUNT++;
  FC_FILE_PATHS[key] = path;
}

function fcDropFd(fd: number): void {
  if (FC_FD_PATHS[fd] !== undefined) {
    delete FC_FD_PATHS[fd];
    FC_FD_COUNT--;
  }
}

function fcDropFile(filePtr: NativePointer): void {
  if (!filePtr || filePtr.isNull()) return;
  const key = filePtr.toString();
  if (FC_FILE_PATHS[key] !== undefined) {
    delete FC_FILE_PATHS[key];
    FC_FILE_COUNT--;
  }
}

// Scan a just-filled buffer: run the lexicon match against its printable content and, if the
// content looks like a dropped payload (DEX/CDEX/ELF/ZIP magic), hand it to dumpBuffer. Deduped
// on tag+path so a tight read loop over the same /proc file logs at most once per distinct hit.
function fcInspectBuffer(
  funcName: string,
  path: string,
  bufPtr: NativePointer,
  len: number,
  context: CpuContext
): void {
  if (!bufPtr || bufPtr.isNull() || len <= 0) return;
  const scanLen = len < FC_SCAN_CAP ? len : FC_SCAN_CAP;

  // Payload magic first: dropped DEX/ELF/ZIP rarely survives as printable UTF-8, so sniff
  // the raw bytes before the string path. Only when at least a full 4-byte magic is present.
  // dumpBuffer itself no-ops to a magic+size+preview line unless config.dumpPayloads is set,
  // so this is safe to call on every interesting write/read.
  if (scanLen >= 4) {
    try {
      const magic = payloadMagic(bufPtr);
      if (magic) {
        const msig = "FCMAGIC|" + funcName + "|" + path + "|" + magic;
        if (!hasSeen(msig)) {
          markSeen(msig);
          // Payload announcement: legacy printed this in PURPLE (a payload event), distinct
          // from the RED anti-debug/anti-frida string detections below - log.dump preserves
          // that PURPLE severity.
          log.dump(TAG, magic.toUpperCase() + " payload seen via " + funcName + " on " + path);
          // Dump the FULL bytes-read (dumpBuffer applies its own 16 MB cap); `scanLen` only
          // bounds the magic-sniff and lexicon scan, not the recovered-payload dump.
          try {
            dumpBuffer("filecontent-" + funcName, bufPtr, len);
          } catch (e) {}
        }
      }
    } catch (e) {}
  }

  // String/lexicon match against the printable content (TracerPid:, frida, magisk, 27042, ...).
  let content = "";
  try {
    const ba = bufPtr.readByteArray(scanLen);
    if (ba) {
      const bytes = new Uint8Array(ba);
      const chars: number[] = [];
      for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) chars.push(b);
      }
      for (let j = 0; j < chars.length; j += 8192) {
        content += String.fromCharCode(...chars.slice(j, j + 8192));
      }
    }
  } catch (e) {
    return;
  }
  if (!content) return;

  // Format-aware anti-analysis detection the generic lexicon cannot express:
  // - TracerPid in /proc/self/status: a NONZERO value means a debugger/Frida is attached.
  // - Frida default ports 27042/27043 in /proc/net/tcp, where the local port is UPPERCASE HEX
  //   (27042 -> 69A2, 27043 -> 69A3), so the decimal lexicon tokens can never match here.
  try {
    if (path.indexOf("/status") !== -1) {
      const tm = content.match(/TracerPid:\s*([0-9]+)/);
      if (tm && tm[1] !== "0") {
        const tsig = "TRACERPID|" + path + "|" + tm[1];
        if (!hasSeen(tsig)) {
          markSeen(tsig);
          log.detect(
            "ANTI-DEBUG",
            "TracerPid=" + tm[1] + " read from " + path + " (a debugger/Frida is attached)"
          );
        }
      }
    }
    if (path.indexOf("/proc/net/tcp") !== -1 && /:(69A2|69A3)\b/i.test(content)) {
      const psig = "FRIDAPORT|" + path;
      if (!hasSeen(psig)) {
        markSeen(psig);
        log.detect("ANTI-FRIDA", "Frida default port (27042/27043) scan detected in " + path);
      }
    }
  } catch (e) {}

  // G-TRACE: copy the context param to a local before building the thunk - scan() invokes
  // the callback bare, so it must close over a plain local, never `this`.
  const ctx = context;
  scan("FILE-CONTENT " + funcName + " (" + path + ")", content, () => getNativeBacktrace(ctx));
}

const mod: DecloakerModule = {
  id: "file-content",
  tag: TAG,
  description:
    "Inspects file read/write buffers for cloaking artifacts on paths already flagged as interesting",
  enabledByDefault: true,
  install() {
    // ---- 1. fd/FILE* -> path recorders (detection-only; NO spoofing here). ----
    // These attach independently of any I/O-spoofing module's copies: that module does not
    // expose the retval->path mapping we need, and re-using its onLeave would entangle our
    // map with its active-bypass logic. Multiple Interceptor.attach on the same libc export
    // is allowed. We only READ retval and record; we never mutate it.

    // open/openat: path is arg[argIdx], new fd is the return value.
    (
      [
        ["open", 0],
        ["openat", 1],
      ] as [string, number][]
    ).forEach(([fn, argIdx]) => {
      const p = getExportSafe("libc.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            this.fcPath = readStrSafe(args[argIdx]);
          },
          onLeave: function (this: IC, retval) {
            if (!this.fcPath) return;
            fcRecordFd(retval.toInt32(), this.fcPath);
          },
        });
      } catch (e: any) {
        log.warn(TAG, "failed to hook " + fn + ": " + e.message);
      }
    });

    // fopen: path is arg0, FILE* is the return value.
    {
      const p = getExportSafe("libc.so", "fopen");
      if (p) {
        try {
          Interceptor.attach(p, {
            onEnter: function (this: IC, args) {
              this.fcPath = readStrSafe(args[0]);
            },
            onLeave: function (this: IC, retval) {
              if (!this.fcPath) return;
              fcRecordFile(retval, this.fcPath);
            },
          });
        } catch (e: any) {
          log.warn(TAG, "failed to hook fopen: " + e.message);
        }
      }
    }

    // close/fclose: drop the mapping so a recycled fd/FILE* cannot alias a stale path.
    // These run unconditionally (cheap hashmap delete) - gating them would desync the maps.
    {
      const pc = getExportSafe("libc.so", "close");
      if (pc) {
        try {
          Interceptor.attach(pc, {
            onEnter: function (this: IC, args) {
              fcDropFd(args[0].toInt32());
            },
          });
        } catch (e: any) {
          log.warn(TAG, "failed to hook close: " + e.message);
        }
      }
      const pf = getExportSafe("libc.so", "fclose");
      if (pf) {
        try {
          Interceptor.attach(pf, {
            onEnter: function (this: IC, args) {
              fcDropFile(args[0]);
            },
          });
        } catch (e: any) {
          log.warn(TAG, "failed to hook fclose: " + e.message);
        }
      }
    }

    // ---- 2. Raw read-back: read / pread64 / pread. GATE = fd present in FC_FD_PATHS. ----
    // read/pread are EXTREMELY hot. We do the map lookup in onEnter and set this.fcSkip so the
    // vast majority of calls (fd not interesting) bail immediately without capturing anything.
    // read(fd,buf,n) and pread64(fd,buf,n,off) share fd=arg0, buf=arg1, retval=bytes read.
    ["read", "pread64", "pread"].forEach((fn) => {
      const p = getExportSafe("libc.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            // Content gate: only fds whose backing path we recorded as /proc/ or a
            // target path are ever inspected - normal file reads are skipped outright.
            const path = FC_FD_PATHS[args[0].toInt32()];
            if (path === undefined || !isTargetCaller(this.returnAddress)) {
              this.fcSkip = true;
              return;
            }
            this.fcSkip = false;
            this.fcPath = path;
            this.fcBuf = args[1];
            this.fcCtx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.fcSkip) return;
            const n = retval.toInt32();
            if (n <= 0) return;
            fcInspectBuffer(fn, this.fcPath, this.fcBuf, n, this.fcCtx);
          },
        });
      } catch (e: any) {
        log.warn(TAG, "failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- 3. stdio read-back: fread / fgets. GATE = FILE* present in FC_FILE_PATHS. ----
    // fread(ptr, size, nmemb, FILE*): buffer arg0, FILE* arg3, retval = items read.
    {
      const p = getExportSafe("libc.so", "fread");
      if (p) {
        try {
          Interceptor.attach(p, {
            onEnter: function (this: IC, args) {
              const path = FC_FILE_PATHS[args[3].toString()];
              if (path === undefined || !isTargetCaller(this.returnAddress)) {
                this.fcSkip = true;
                return;
              }
              this.fcSkip = false;
              this.fcPath = path;
              this.fcBuf = args[0];
              this.fcSize = args[1].toInt32();
              this.fcCtx = this.context;
            },
            onLeave: function (this: IC, retval) {
              if (this.fcSkip) return;
              const items = retval.toInt32();
              if (items <= 0 || this.fcSize <= 0) return;
              let bytes = items * this.fcSize;
              if (bytes <= 0) return;
              if (bytes > FC_SCAN_CAP) bytes = FC_SCAN_CAP;
              fcInspectBuffer("fread", this.fcPath, this.fcBuf, bytes, this.fcCtx);
            },
          });
        } catch (e: any) {
          log.warn(TAG, "failed to hook fread: " + e.message);
        }
      }
    }

    // fgets(buf, size, FILE*): line buffer arg0, FILE* arg2, retval = buf (or NULL at EOF).
    {
      const p = getExportSafe("libc.so", "fgets");
      if (p) {
        try {
          Interceptor.attach(p, {
            onEnter: function (this: IC, args) {
              const path = FC_FILE_PATHS[args[2].toString()];
              if (path === undefined || !isTargetCaller(this.returnAddress)) {
                this.fcSkip = true;
                return;
              }
              this.fcSkip = false;
              this.fcPath = path;
              this.fcBuf = args[0];
              this.fcCtx = this.context;
            },
            onLeave: function (this: IC, retval) {
              if (this.fcSkip || retval.isNull()) return;
              // NUL-terminated line; readStrSafe bounds it, then scan the string directly.
              const line = readStrSafe(this.fcBuf, FC_SCAN_CAP);
              if (!line) return;
              // G-TRACE: copy the stashed context/path to locals before building the thunk -
              // scan() calls it bare, so it must never close over `this`.
              const ctx = this.fcCtx;
              const path = this.fcPath;
              scan("FILE-CONTENT fgets (" + path + ")", line, () => getNativeBacktrace(ctx));
            },
          });
        } catch (e: any) {
          log.warn(TAG, "failed to hook fgets: " + e.message);
        }
      }
    }

    // ---- 4. getline / getdelim. GATE = FILE* present in FC_FILE_PATHS. ----
    // getline(char **lineptr, size_t *n, FILE*): the malware-favourite for scanning /proc line
    // by line. The line lives at *lineptr (arg0 is char**), the FILE* is arg2, retval = length.
    ["getline", "getdelim"].forEach((fn) => {
      const p = getExportSafe("libc.so", fn);
      if (!p) return;
      // getdelim adds an int delim arg (arg2), pushing FILE* from arg2 to arg3.
      const fileIdx = fn === "getdelim" ? 3 : 2;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            const path = FC_FILE_PATHS[args[fileIdx].toString()];
            if (path === undefined || !isTargetCaller(this.returnAddress)) {
              this.fcSkip = true;
              return;
            }
            this.fcSkip = false;
            this.fcPath = path;
            this.fcLinePtrPtr = args[0]; // char** - the line buffer is written by the callee
            this.fcCtx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.fcSkip) return;
            const n = retval.toInt32();
            if (n <= 0) return;
            let linePtr: NativePointer | null = null;
            try {
              linePtr = this.fcLinePtrPtr.readPointer();
            } catch (e) {
              return;
            }
            if (!linePtr || linePtr.isNull()) return;
            fcInspectBuffer(fn, this.fcPath, linePtr, n, this.fcCtx);
          },
        });
      } catch (e: any) {
        log.warn(TAG, "failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- 5. Writes: write / pwrite64 / pwrite. Inspect DROPPED content. ----
    // GATE: only inspect when the destination fd's path is interesting (in FC_FD_PATHS).
    // Buffer content is the SOURCE (valid at onEnter), so we gate on the fd map before touching
    // anything - normal writes to normal files are skipped with no buffer read.
    // write(fd,buf,n) and pwrite64(fd,buf,n,off) share fd=arg0, buf=arg1, len=arg2.
    ["write", "pwrite64", "pwrite"].forEach((fn) => {
      const p = getExportSafe("libc.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            const path = FC_FD_PATHS[args[0].toInt32()];
            if (path === undefined || !isTargetCaller(this.returnAddress)) return;
            const len = args[2].toInt32();
            if (len <= 0) return;
            fcInspectBuffer(fn, path, args[1], len, this.context);
          },
        });
      } catch (e: any) {
        log.warn(TAG, "failed to hook " + fn + ": " + e.message);
      }
    });

    // fwrite(ptr, size, nmemb, FILE*): buffer arg0, FILE* arg3.
    {
      const p = getExportSafe("libc.so", "fwrite");
      if (p) {
        try {
          Interceptor.attach(p, {
            onEnter: function (this: IC, args) {
              const path = FC_FILE_PATHS[args[3].toString()];
              if (path === undefined || !isTargetCaller(this.returnAddress)) return;
              const size = args[1].toInt32();
              const nmemb = args[2].toInt32();
              if (size <= 0 || nmemb <= 0) return;
              let bytes = size * nmemb;
              if (bytes <= 0) return;
              if (bytes > FC_SCAN_CAP) bytes = FC_SCAN_CAP;
              fcInspectBuffer("fwrite", path, args[0], bytes, this.context);
            },
          });
        } catch (e: any) {
          log.warn(TAG, "failed to hook fwrite: " + e.message);
        }
      }
    }

    log.setup(
      TAG,
      "Hooked file-content read-back (read/pread64/fread/fgets/getline/getdelim) " +
        "and writes (write/pwrite64/fwrite), gated on fd/FILE*->path map."
    );
  },
};

export default mod;
