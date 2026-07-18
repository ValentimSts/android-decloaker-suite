// Ported from legacy decloaker.js hookFsRecon (lines 2463-2639), plus its
// module-private _readMntent, _attachTwoPathDetect, and _DIRENT_DNAME_OFF.
//
// Covers directory enumeration, mount-table parsing, filesystem-stat, and
// mount/rename/unlink syscalls that the path-EXISTENCE hooks (open/stat/access
// family, elsewhere) do NOT touch. Everything here is DETECTION ONLY - it
// never mutates the sample's behavior.
//
// GATING (per the flood rules):
//   - Every hook is gated on isTargetCaller(this.returnAddress) first.
//   - opendir/statfs/mount/rename/unlink families are LOW frequency (per open
//     dir / per fs op), so plain detection on the path arg is enough and
//     self-dedupes via scan()'s ALERT_HISTORY.
//   - readdir/readdir64 are the ONLY hot funcs here. To avoid flooding we NEVER
//     log per call: gated on isTargetCaller, we read the single d_name C-string
//     at the bionic offset and hand it to scan(), which no-ops unless it
//     matches the lexicon (frida-server/su/magisk/...) and then dedupes. We scan
//     every entry name (directory contents are exactly where the artifact name
//     shows up) but log at most once per unique name.

import { log } from "../core/logger";
import { getExportSafe, readStrSafe } from "../core/memory";
import { getNativeBacktrace, isTargetCaller } from "../core/backtrace";
import { safeAttachDetect } from "../core/attach";
import { scan } from "../filters/matcher";
import type { IC, DecloakerModule } from "../types";

const TAG = "FS-RECON";

// bionic `struct dirent` layout is identical on 32- and 64-bit Android:
//   uint64_t d_ino (@0, 8) + int64_t d_off (@8, 8) + uint16_t d_reclen (@16, 2)
//   + uint8_t d_type (@18, 1) => char d_name[] @ 19 (char[] needs no padding).
const DIRENT_DNAME_OFF = 19;

// `struct mntent` (bionic/glibc): char *mnt_fsname (device) at offset 0, then
// char *mnt_dir (mount point) at offset pointerSize. Shared by the
// getmntent/getmntent_r onLeave handlers and the hasmntopt onEnter handler
// below, so it lives at module scope rather than nested in install().
function readMntent(mntPtr: NativePointer, source: string, context: CpuContext): void {
  try {
    if (mntPtr == null || mntPtr.isNull()) return;
    const fsname = readStrSafe(mntPtr.readPointer()); // mnt_fsname
    const dir = readStrSafe(mntPtr.add(Process.pointerSize).readPointer()); // mnt_dir
    const combined = fsname + " " + dir;
    scan(source, combined, () => getNativeBacktrace(context));
  } catch (e) {}
}

// Two-path detection-only attach (mount/rename/renameat2): scan BOTH paths.
// argA/argB are the arg indices holding the two C-string paths. Single-path
// cases are handled by the shared safeAttachDetect(mod, func, argIndex) helper.
function attachTwoPathDetect(moduleName: string, funcName: string, argA: number, argB: number): boolean {
  const p = getExportSafe(moduleName, funcName);
  if (!p) return false;
  try {
    Interceptor.attach(p, {
      onEnter: function (this: IC, args) {
        if (!isTargetCaller(this.returnAddress)) return;
        const a = readStrSafe(args[argA]);
        const b = readStrSafe(args[argB]);
        const ctx = this.context;
        if (a) scan(funcName + " (from)", a, () => getNativeBacktrace(ctx));
        if (b) scan(funcName + " (to)", b, () => getNativeBacktrace(ctx));
      },
    });
    log.setup(TAG, "Hooked: " + funcName);
    return true;
  } catch (e: any) {
    log.warn(TAG, "Failed to hook " + funcName + ": " + e.message);
    return false;
  }
}

const mod: DecloakerModule = {
  id: "fs-recon",
  tag: TAG,
  description: "Detects directory enumeration, mount-table parsing, fs-stat, and mount/rename/unlink syscalls",
  enabledByDefault: true,
  install() {
    // ----- Directory enumeration: opendir (path arg0) -----
    // Low frequency (once per directory opened) so plain detection on arg0 is fine.
    safeAttachDetect("libc.so", "opendir", 0);

    // ----- readdir / readdir64: read returned `struct dirent*` d_name -----
    // HOT path. Gated on isTargetCaller; we read one NUL-terminated C-string per
    // call and feed it to scan() (no unconditional logging), so non-matching
    // entries are silent and matching names (frida-server/su/magisk/...) log at
    // most once each via scan's dedup. On 64-bit bionic readdir IS readdir64
    // (same symbol); the duplicate listener self-dedupes via scan.
    ["readdir", "readdir64"].forEach(function (funcName) {
      const p = getExportSafe("libc.so", funcName);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC) {
            // Cheap module gate BEFORE any work; flag carried to onLeave.
            this.skip = !isTargetCaller(this.returnAddress);
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip || retval == null || retval.isNull()) return;
            // readStrSafe is already null/fault-safe; retval+offset is a valid read.
            const name = readStrSafe(retval.add(DIRENT_DNAME_OFF));
            // Skip "." / ".." and empty names - zero signal, avoids churn.
            if (!name || name === "." || name === "..") return;
            const ctx = this.ctx;
            scan(funcName + " d_name", name, () => getNativeBacktrace(ctx));
          },
        });
        log.setup(TAG, "Hooked: " + funcName + " (d_name @ " + DIRENT_DNAME_OFF + ")");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + funcName + ": " + e.message);
      }
    });

    // ----- Mount-table parsing: getmntent / getmntent_r return `struct mntent*` -----
    // Classic root/Magisk detection walks /proc/mounts via setmntent+getmntent
    // looking for suspicious mnt_fsname/mnt_dir (e.g. magisk, /data/adb). Both
    // funcs return the populated `struct mntent*` (getmntent_r returns its arg1
    // mntent* on success, NULL at EOF). Read both fields on leave.
    ["getmntent", "getmntent_r"].forEach(function (funcName) {
      const p = getExportSafe("libc.so", funcName);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC) {
            this.skip = !isTargetCaller(this.returnAddress);
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip || retval == null || retval.isNull()) return;
            readMntent(retval, funcName, this.ctx);
          },
        });
        log.setup(TAG, "Hooked: " + funcName);
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + funcName + ": " + e.message);
      }
    });

    // hasmntopt(const struct mntent *mnt, const char *opt): scan the mntent it
    // inspects (arg0) plus the option string (arg1). Self-skips via getExportSafe
    // when the target does not export hasmntopt.
    (function () {
      const p = getExportSafe("libc.so", "hasmntopt");
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const ctx = this.context;
            readMntent(args[0], "hasmntopt (mnt)", ctx);
            const opt = readStrSafe(args[1]);
            if (opt) scan("hasmntopt (opt)", opt, () => getNativeBacktrace(ctx));
          },
        });
        log.setup(TAG, "Hooked: hasmntopt");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook hasmntopt: " + e.message);
      }
    })();

    // ----- Filesystem stat: statfs / statfs64 / statvfs / statvfs64 (path arg0) -----
    // Used to fingerprint filesystem type/flags of suspicious mount points. Low frequency.
    safeAttachDetect("libc.so", "statfs", 0);
    safeAttachDetect("libc.so", "statfs64", 0);
    safeAttachDetect("libc.so", "statvfs", 0);
    safeAttachDetect("libc.so", "statvfs64", 0);

    // ----- mount(source, target, ...) / umount2(target,flags) / umount(target) -----
    // mount: scan both source device (arg0) and target mountpoint (arg1).
    // umount2/umount: single target path at arg0.
    attachTwoPathDetect("libc.so", "mount", 0, 1);
    safeAttachDetect("libc.so", "umount2", 0);
    safeAttachDetect("libc.so", "umount", 0);

    // ----- rename(old,new) / renameat2/renameat: hiding/moving artifacts -----
    // rename paths are args 0 and 1; renameat2/renameat paths are args 1 and 3
    // (dirfds occupy args 0 and 2).
    attachTwoPathDetect("libc.so", "rename", 0, 1);
    attachTwoPathDetect("libc.so", "renameat2", 1, 3);
    attachTwoPathDetect("libc.so", "renameat", 1, 3);

    // ----- unlink(path) / unlinkat(dirfd,path,flags) / remove(path) -----
    safeAttachDetect("libc.so", "unlink", 0);
    safeAttachDetect("libc.so", "unlinkat", 1);
    safeAttachDetect("libc.so", "remove", 0);

    log.setup(TAG, "Filesystem recon hooks installed (opendir/readdir/getmntent/statfs/mount/rename/unlink)");
  },
};

export default mod;
