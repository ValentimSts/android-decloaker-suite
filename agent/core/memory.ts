import { config } from "../config";
import { log } from "./logger";
import { hasSeen, markSeen } from "./dedup";

// `Process`, `File`, and `NativePointer` are ambient frida-gum globals - do
// NOT import them from "frida-gum".

export function getExportSafe(moduleName: string, funcName: string): NativePointer | null {
  try {
    const mod = Process.getModuleByName(moduleName);
    return mod.getExportByName(funcName);
  } catch (e) {
    return null;
  }
}

export function readStrSafe(ptr: NativePointer, limit?: number): string {
  try {
    if (ptr != null && !ptr.isNull()) {
      if (limit) return ptr.readUtf8String(limit) || "";
      return ptr.readUtf8String() || "";
    }
  } catch (e) {}
  return "";
}

// Hex string of up to maxLen bytes at p (default 64). Null/fault safe.
export function hexPreview(p: NativePointer, maxLen?: number): string {
  try {
    if (!p || p.isNull()) return "";
    const n = maxLen || 64;
    const bytes = new Uint8Array(p.readByteArray(n) as ArrayBuffer);
    const len = bytes.length;
    let hex = "";

    if (!config.truncateHex || len <= 24) {
      for (let i = 0; i < len; i++) {
        const h = (bytes[i] & 0xff).toString(16);
        hex += h.length === 1 ? "0" + h : h;
      }
    } else {
      for (let i = 0; i < 8; i++) {
        const h = (bytes[i] & 0xff).toString(16);
        hex += h.length === 1 ? "0" + h : h;
      }
      hex += "...";
      for (let i = len - 8; i < len; i++) {
        const h = (bytes[i] & 0xff).toString(16);
        hex += h.length === 1 ? "0" + h : h;
      }
      hex += " (" + len + " bytes)";
    }
    return hex;
  } catch (e) {
    return "";
  }
}

// Identify a decrypted/unpacked payload by its leading magic bytes.
export function payloadMagic(p: NativePointer): "dex" | "cdex" | "elf" | "zip" | null {
  try {
    if (!p || p.isNull()) return null;
    const b = new Uint8Array(p.readByteArray(4) as ArrayBuffer);
    if (b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a) return "dex"; // "dex\n"
    if (b[0] === 0x63 && b[1] === 0x64 && b[2] === 0x65 && b[3] === 0x78) return "cdex"; // "cdex"
    if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "elf"; // 0x7f ELF
    if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return "zip"; // PK..
    return null;
  } catch (e) {
    return null;
  }
}

// Log (always) and, when dumpPayloads is on, write a captured buffer to
// dumpDir. Deduped.
export function dumpBuffer(tag: string, p: NativePointer, len: number): void {
  try {
    if (!p || p.isNull() || !len || len <= 0) return;
    const magic = payloadMagic(p);
    const sig = "dump|" + tag + "|" + p + "|" + len;
    if (hasSeen(sig)) return;
    markSeen(sig);
    log.dump(
      "DUMP",
      tag + " size=" + len + (magic ? " magic=" + magic : "") + " head=" + hexPreview(p, 32)
    );
    if (config.dumpPayloads) {
      const cap = len < 16 * 1024 * 1024 ? len : 16 * 1024 * 1024; // safety cap 16 MB
      const fname =
        config.dumpDir +
        "/amas_" +
        String(tag).replace(/[^a-zA-Z0-9_.-]/g, "_") +
        "_" +
        String(p).replace(/^0x/, "") +
        (magic ? "." + magic : ".bin");
      const f = new File(fname, "wb");
      f.write(p.readByteArray(cap) as ArrayBuffer);
      f.close();
      log.dump("DUMP", "    -> dumped to " + fname);
    }
  } catch (e: any) {
    log.warn("DUMP", "    -> [!] dumpBuffer error: " + e.message);
  }
}
