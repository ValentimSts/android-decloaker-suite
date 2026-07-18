// Ported from legacy decloaker.js hookArtDexLoaders (lines 1780-2065), plus its
// module-private helpers reportArtDexBuffer (1798) and attachJniOnLoad (1838).
//
// ==========================================
// ART-INTERNAL DEX LOADERS + JNI_OnLoad (PACKER-PROOF)
// ==========================================
//
// Survives Java-DCL bypass: packers that decrypt a dex in memory and feed it
// straight to the ART DexFileLoader never touch dalvik.system.*ClassLoader, so
// the java-dcl module misses them. We hook the native libart.so entry points
// that ALL dex loading funnels through (in-memory + file-path), plus
// per-module JNI_OnLoad.
//
// Does NOT duplicate the libart module (RegisterNatives / FindClass) or
// java-dcl module. NOTE: dlopen/android_dlopen_ext are ALSO attached by the
// library-loading module for string detection. Frida stacks independent
// listeners on the same address, so attaching again here (for JNI_OnLoad
// discovery only) is safe and intentional.

import { log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { getExportSafe, readStrSafe, hexPreview, payloadMagic, dumpBuffer } from "../core/memory";
import { getNativeBacktrace, formatBacktrace, isTargetCaller } from "../core/backtrace";
import type { IC, DecloakerModule } from "../types";

const TAG = "ART-DEX";
const JNI_TAG = "JNI_OnLoad";

// Small module-private helper: given a base pointer + a claimed size, decide
// whether the buffer really looks like a dex/cdex payload and, if so, report
// + dump it once. Uses shared payloadMagic()/dumpBuffer(); dedups on
// (tag|base|magic|len) via hasSeen/markSeen.
function reportArtDexBuffer(
  tag: string,
  basePtr: NativePointer | null,
  size: NativePointer | null,
  ctx: CpuContext
): boolean {
  try {
    if (basePtr == null || basePtr.isNull()) return false;
    const magic = payloadMagic(basePtr);
    // Only act on genuine dex/cdex magic - avoids dumping garbage when a
    // symbol's real signature does not match our (base,size) guess.
    if (magic !== "dex" && magic !== "cdex") return false;

    let len = 0;
    try {
      len = size ? size.toInt32() : 0;
    } catch (e) {
      len = 0;
    }
    // Sanity-bound the length; ART dex regions are well under this cap.
    if (len < 8 || len > 64 * 1024 * 1024) len = 0;

    const signature = "artdex|" + tag + "|" + basePtr + "|" + magic + "|" + len;
    if (hasSeen(signature)) return true;
    markSeen(signature);

    let preview = "";
    try {
      preview = hexPreview(basePtr, 16);
    } catch (e) {}

    const bt = getNativeBacktrace(ctx);
    log.detect(
      TAG,
      "In-memory dex load via " + tag,
      [
        ["Base", basePtr.toString()],
        ["Size", String(len)],
        ["Magic", magic],
        ["Preview", preview],
      ],
      bt ? formatBacktrace(bt) : undefined
    );

    // dumpBuffer writes to config.dumpDir only when config.dumpPayloads is
    // set; otherwise it just logs magic+size+preview. It no-ops on len <= 0,
    // so an untrusted size still gets logged above without dumping garbage.
    try {
      dumpBuffer("art-dex", basePtr, len);
    } catch (e: any) {
      log.warn(TAG, "dumpBuffer failed: " + e.message);
    }

    return true;
  } catch (e: any) {
    log.warn(TAG, "reportArtDexBuffer error: " + e.message);
    return false;
  }
}

// Attach to JNI_OnLoad of a single module (if it exports one) so we log the
// exact owning library + backtrace the moment ART invokes native init - the
// classic place a packer stub kicks off. Dedups per module so re-enumeration
// never double-hooks.
function attachJniOnLoad(modName: string): void {
  try {
    if (!modName) return;
    const sig = "jnionload|" + modName;
    if (hasSeen(sig)) return;

    const p = getExportSafe(modName, "JNI_OnLoad");
    if (!p || p.isNull()) return;

    // Mark before attaching so a throw inside attach still records the
    // module (prevents a broken module from being retried on every dlopen).
    markSeen(sig);
    const onLoadPtr = p;
    Interceptor.attach(onLoadPtr, {
      onEnter: function (this: IC) {
        // JNI_OnLoad(JavaVM*, void*): no cheap path/string here, so this is
        // detection-only and low frequency (once per library init). No
        // gating beyond the per-module dedup above is needed.
        const ctx = this.context;
        const bt = getNativeBacktrace(ctx);
        log.detect(
          JNI_TAG,
          "Native init invoked in: " + modName,
          [["JNI_OnLoad", onLoadPtr.toString()]],
          bt ? formatBacktrace(bt) : undefined
        );
      },
    });
    log.setup(JNI_TAG, "Hooked JNI_OnLoad in " + modName);
  } catch (e: any) {
    log.warn(JNI_TAG, "attachJniOnLoad(" + modName + ") failed: " + e.message);
  }
}

const mod: DecloakerModule = {
  id: "art-dex-loaders",
  tag: TAG,
  description: "Hooks ART in-memory dex loaders, the file-path dex loader, and per-module JNI_OnLoad",
  enabledByDefault: true,
  install() {
    // ---- 1. ART-internal in-memory dex loaders (packer-proof) ----------------
    //
    // Robust to symbol-name variation across Android versions: we scan BOTH
    // exports and (mangled, internal) symbols of libart.so, matching by
    // substring. Names of interest carry "DexFile" together with one of the
    // Open* / loader variants:
    //   - OpenMemory / OpenCommon (pre-Q internal Art::DexFile::Open*)
    //   - ArtDexFileLoader::Open* (Q+ moved loading into DexFileLoader)
    //   - openInMemoryDexFile* (JNI-facing DexFile bridge)
    // These take a const uint8_t* base and a size_t size among their args,
    // but the exact ARG INDEX varies by version/overload, so instead of
    // trusting a fixed index we probe the first several pointer args for
    // real dex/cdex magic and use the following arg as the candidate size.
    // Wrapped per-symbol in try/catch.
    const hookedNames: string[] = [];
    const seenAddr: Record<string, true> = {};

    function looksLikeDexLoader(name: string): boolean {
      if (!name) return false;
      if (name.indexOf("DexFile") === -1) return false;
      if (name.indexOf("CheckJNI") !== -1) return false;
      return (
        name.indexOf("OpenMemory") !== -1 ||
        name.indexOf("OpenCommon") !== -1 ||
        name.indexOf("openInMemoryDexFile") !== -1 ||
        name.indexOf("ArtDexFileLoader") !== -1
      );
    }

    function attachDexLoader(name: string, address: NativePointer): void {
      if (!address || address.isNull()) return;
      const key = "" + address;
      if (seenAddr[key]) return;
      seenAddr[key] = true;
      try {
        Interceptor.attach(address, {
          onEnter: function (this: IC, args) {
            // libart internal - gate on target caller so framework dex
            // loading (system apps, GMS) does not flood the log.
            if (!isTargetCaller(this.returnAddress)) return;
            const ctx = this.context;
            // Probe the first few pointer args for dex/cdex magic; the size
            // is conventionally the arg immediately after the base pointer.
            // We stop at the first arg whose bytes carry a real magic.
            for (let k = 0; k < 6; k++) {
              let basePtr: NativePointer | null = null;
              try {
                basePtr = args[k];
              } catch (e) {
                break;
              }
              if (basePtr == null || basePtr.isNull()) continue;
              let m: "dex" | "cdex" | "elf" | "zip" | null = null;
              try {
                m = payloadMagic(basePtr);
              } catch (e) {
                m = null;
              }
              if (m === "dex" || m === "cdex") {
                let sizeArg: NativePointer | null = null;
                try {
                  sizeArg = args[k + 1];
                } catch (e) {
                  sizeArg = null;
                }
                if (reportArtDexBuffer(name, basePtr, sizeArg, ctx)) return;
              }
            }
          },
        });
        hookedNames.push(name);
      } catch (e: any) {
        log.warn(TAG, "Failed to hook ART loader " + name + ": " + e.message);
      }
    }

    try {
      const libart = Process.getModuleByName("libart.so");

      // Exports first (cheap), then the full symbol table (mangled internals).
      try {
        libart.enumerateExports().forEach(function (exp) {
          if (exp.type === "function" && looksLikeDexLoader(exp.name)) {
            attachDexLoader(exp.name, exp.address);
          }
        });
      } catch (e: any) {
        log.warn(TAG, "libart export enumeration failed: " + e.message);
      }
      try {
        libart.enumerateSymbols().forEach(function (sym) {
          if (sym.address && !sym.address.isNull() && looksLikeDexLoader(sym.name)) {
            attachDexLoader(sym.name, sym.address);
          }
        });
      } catch (e: any) {
        log.warn(TAG, "libart symbol enumeration failed: " + e.message);
      }

      if (hookedNames.length > 0) {
        log.setup(TAG, "Hooked " + hookedNames.length + " ART in-memory dex loader(s): " + hookedNames.join(", "));
      } else {
        log.warn(TAG, "No ART in-memory dex loader symbols matched on this build.");
      }
    } catch (e: any) {
      log.warn(TAG, "hookArtDexLoaders: libart.so unavailable: " + e.message);
    }

    // ---- 2. Exported DexFile_openDexFileNative (file-path dex loading) --------
    // This is the JNI-registered entry behind DexPathList; catches on-disk
    // dex/apk paths even when the Java DexClassLoader hook is bypassed via
    // reflection.
    try {
      let openNativeName = "DexFile_openDexFileNative";
      const libart2 = Process.getModuleByName("libart.so");
      let openNativePtr: NativePointer | null = null;
      // Exported name is decorated on some builds; match by substring over exports.
      libart2.enumerateExports().forEach(function (exp) {
        if (openNativePtr) return;
        if (exp.type === "function" && exp.name.indexOf("openDexFileNative") !== -1) {
          openNativePtr = exp.address;
          openNativeName = exp.name;
        }
      });
      if (openNativePtr) {
        Interceptor.attach(openNativePtr, {
          onEnter: function (this: IC) {
            if (!isTargetCaller(this.returnAddress)) return;
            const ctx = this.context;
            // Signature: (JNIEnv*, jclass, jstring sourceName, jstring outputName, ...)
            // The jstring args are Java String objects, not char*; we cannot
            // readUtf8String them directly, so we log the invocation +
            // backtrace and let the Java DCL / file I/O hooks surface the
            // actual path.
            const bt = getNativeBacktrace(ctx);
            log.detect(
              TAG,
              openNativeName + " invoked (file/path dex load)",
              undefined,
              bt ? formatBacktrace(bt) : undefined
            );
          },
        });
        log.setup(TAG, "Hooked ART file loader: " + openNativeName);
      } else {
        log.warn(TAG, "DexFile_openDexFileNative not exported on this build.");
      }
    } catch (e: any) {
      log.warn(TAG, "Failed to hook DexFile_openDexFileNative: " + e.message);
    }

    // ---- 3. JNI_OnLoad per module (existing + newly loaded) ------------------
    // Hook JNI_OnLoad of every currently-mapped module, then hook the dlopen
    // family (onLeave) to catch libraries loaded LATER - a decrypted packer
    // stage - and attach to its JNI_OnLoad the moment it appears.
    // Detection-only, never spoofs.
    try {
      Process.enumerateModules().forEach(function (m) {
        attachJniOnLoad(m.name);
      });
    } catch (e: any) {
      log.warn(TAG, "JNI_OnLoad module enumeration failed: " + e.message);
    }

    // GATING NOTE: dlopen/android_dlopen_ext only fire on library loads (not
    // a hot path), so no content gating is needed beyond the per-module
    // hasSeen/markSeen dedup inside attachJniOnLoad. The library-loading
    // module also attaches here for string detection; Frida stacks
    // listeners, so this second attach is fine.
    ["libdl.so", "libc.so"].forEach(function (libName) {
      ["dlopen", "android_dlopen_ext"].forEach(function (fnName) {
        try {
          const p = getExportSafe(libName, fnName);
          if (!p) return;
          Interceptor.attach(p, {
            onEnter: function (this: IC, args) {
              // arg0 is the filename for both dlopen and android_dlopen_ext.
              this.reqPath = readStrSafe(args[0]);
            },
            onLeave: function (this: IC, retval) {
              if (retval.isNull()) return;
              try {
                // Resolve the just-loaded module. On Android, dlopen returns
                // an opaque soinfo* HANDLE, NOT the module's load base, so
                // findModuleByAddress(handle) usually fails - resolve by the
                // requested basename over the module list first (reliable),
                // and only fall back to the handle as a best effort.
                let attached = false;
                if (this.reqPath) {
                  const base = this.reqPath.split("/").pop();
                  if (base) {
                    Process.enumerateModules().forEach(function (m) {
                      if (m.name === base) {
                        attachJniOnLoad(m.name);
                        attached = true;
                      }
                    });
                  }
                }
                if (!attached) {
                  let owner: Module | null = null;
                  try {
                    owner = Process.findModuleByAddress(retval);
                  } catch (e) {}
                  if (owner) attachJniOnLoad(owner.name);
                }
              } catch (e: any) {
                log.warn(TAG, "post-dlopen JNI_OnLoad resolve failed: " + e.message);
              }
            },
          });
        } catch (e: any) {
          log.warn(TAG, "Failed to hook " + fnName + " (" + libName + ") for JNI_OnLoad: " + e.message);
        }
      });
    });

    log.setup(TAG, "hookArtDexLoaders installed (ART dex loaders + JNI_OnLoad watcher)");
  },
};

export default mod;
