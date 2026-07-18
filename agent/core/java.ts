import Java from "frida-java-bridge";
import { config } from "../config";

// frida-java-bridge IS a real npm module (unlike "frida-gum", whose types are
// ambient globals) - importing its default export is correct and required.
export { Java };

// `Memory` and `NativePointer` are ambient frida-gum globals - do NOT import
// them from "frida-gum".

export function withJava(fn: () => void): void {
  if (!Java.available) return;
  Java.perform(fn);
}

// A Java byte[] as seen from JS: numeric-indexed, signed bytes, with `.length`.
type JByteArray = { length: number; [index: number]: number };

// Convert a Java byte[] (signed bytes) to a lowercase hex string, bounded to
// maxLen bytes so a multi-MB decrypted blob cannot flood the console. When
// config.truncateHex is set and the buffer is large, prints only the first 8
// and last 8 bytes with a byte-count marker. Returns "" for null/empty input.
export function jbytesToHex(jbytes: JByteArray | null | undefined, maxLen?: number): string {
  if (jbytes === null || jbytes === undefined) return "";
  let len = 0;
  try {
    len = jbytes.length;
  } catch (e) {
    return "";
  }
  if (typeof len !== "number" || len === 0) return "";

  const cap = maxLen && maxLen < len ? maxLen : len;
  let hex = "";

  // If truncation is disabled or the buffer is small, print the requested cap
  if (!config.truncateHex || cap <= 24) {
    for (let i = 0; i < cap; i++) {
      const b = jbytes[i] & 0xff;
      hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    if (cap < len) hex += "... [" + len + " bytes total]";
  } else {
    // Truncate drastically: first 8 bytes
    for (let i = 0; i < 8; i++) {
      const b = jbytes[i] & 0xff;
      hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    hex += "...";
    // Last 8 bytes
    for (let i = cap - 8; i < cap; i++) {
      const b = jbytes[i] & 0xff;
      hex += (b < 16 ? "0" : "") + b.toString(16);
    }
    hex += " (" + len + " bytes)";
  }
  return hex;
}

// Decode a Java byte[] to a printable ASCII string for checkAndLog, so a
// decrypted plaintext containing a target token (e.g. "frida", "magisk", a C2
// URL) is matched by the shared lexicon. Non-printable bytes are dropped;
// bounded to maxLen bytes. Returns "" when the buffer is mostly binary (fewer
// than ~40% printable) to avoid noise.
export function jbytesToPrintable(jbytes: JByteArray | null | undefined, maxLen?: number): string {
  if (jbytes === null || jbytes === undefined) return "";
  let len = 0;
  try {
    len = jbytes.length;
  } catch (e) {
    return "";
  }
  if (typeof len !== "number" || len === 0) return "";
  const cap = maxLen && maxLen < len ? maxLen : len;
  let out = "";
  let printable = 0;
  for (let i = 0; i < cap; i++) {
    const b = jbytes[i] & 0xff;
    if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
      out += String.fromCharCode(b);
      printable++;
    }
  }
  if (cap > 0 && printable / cap < 0.4) return "";
  return out;
}

// Copy up to maxLen bytes of a Java byte[] into a native buffer so the shared
// dumpBuffer/payloadMagic helpers (which take a NativePointer) can magic-sniff
// and optionally dump a decrypted second-stage payload. NativePointer.writeByteArray
// does NOT accept a Java array wrapper, so we first build a plain JS array of
// unsigned bytes. Returns { ptr, len } or null.
export function jbytesToNative(
  jbytes: JByteArray | null | undefined,
  maxLen?: number
): { ptr: NativePointer; len: number } | null {
  try {
    if (jbytes === null || jbytes === undefined) return null;
    const len = jbytes.length;
    if (typeof len !== "number" || len <= 0) return null;
    const cap = maxLen && maxLen < len ? maxLen : len;
    const arr = new Array(cap);
    for (let i = 0; i < cap; i++) arr[i] = jbytes[i] & 0xff;
    const p = Memory.alloc(cap);
    p.writeByteArray(arr);
    return { ptr: p, len: cap };
  } catch (e) {
    return null;
  }
}

// Copy a bounded [off, off+n) slice of a Java byte[] into a plain JS array of
// signed bytes that jbytesToHex / jbytesToPrintable can consume (they only
// read [i] and .length).
export function jbytesSlice(
  jbytes: JByteArray | null | undefined,
  off: number,
  n: number,
  maxLen?: number
): number[] {
  const slice: number[] = [];
  try {
    if (jbytes === null || jbytes === undefined) return slice;
    const total = jbytes.length;
    if (typeof total !== "number") return slice;
    const lim = maxLen && maxLen < n ? maxLen : n;
    for (let i = 0; i < lim; i++) {
      const idx = off + i;
      if (idx < 0 || idx >= total) break;
      slice.push(jbytes[idx]);
    }
  } catch (e) {}
  return slice;
}
