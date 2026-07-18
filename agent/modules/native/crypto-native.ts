// Ported from legacy decloaker.js hookCryptoNative (lines 3234-3547), plus its
// module-private CRYPTO_PREVIEW_CAP, cryptoReadForScan, cryptoInspectOutput,
// and cryptoPreviewKeyMaterial helpers.
//
// Native-only malware often decrypts/decompresses second-stage payloads in libcrypto.so
// (BoringSSL EVP/AES) and libz.so, entirely skipping the Java JCA layer that a pure-Java
// hook would catch. We observe the PLAINTEXT (decrypted / decompressed output) plus the
// key/iv material, run it through scan() against the evasion lexicon, and hand any buffer
// to dumpBuffer (which classifies dex/elf/zip magic and, if config.dumpPayloads, writes it
// to config.dumpDir). Detection-only: nothing here mutates the sample.
//
// GATING: every hook is gated by isTargetCaller(this.returnAddress) so we ignore framework
// crypto (GMS, TLS libs) when targetModules is set. These are moderate-frequency calls
// (per crypto block / per payload), NOT per-syscall hot paths, so caller gating suffices.
// We additionally content-gate: we only read/preview/scan when a positive output length was
// produced (outlen > 0), so an empty or failed crypto op emits nothing. Buffer previews are
// bounded by CRYPTO_PREVIEW_CAP to keep hex formatting cheap on large payloads.

import { config } from "../../config";
import { log } from "../../core/logger";
import { hasSeen, markSeen } from "../../core/dedup";
import { getExportSafe, hexPreview, payloadMagic, dumpBuffer } from "../../core/memory";
import { getNativeBacktrace, formatBacktrace, isTargetCaller } from "../../core/backtrace";
import { scan } from "../../filters/matcher";
import type { IC, DecloakerModule } from "../../types";

const TAG = "CRYPTO";

// Max bytes hex-previewed / scanned per crypto output buffer.
const CRYPTO_PREVIEW_CAP = 256;

// Read up to CRYPTO_PREVIEW_CAP bytes at ptrBuf as a printable string for lexicon matching.
// Null-safe and bounded; readByteArray gives us raw bytes without a NUL-termination assumption
// (ciphertext output rarely NUL-terminates). We keep only printable-ish bytes so scan() sees strings.
function cryptoReadForScan(ptrBuf: NativePointer, len: number): string {
  try {
    if (!ptrBuf || ptrBuf.isNull() || len <= 0) return "";
    const capLen = len < CRYPTO_PREVIEW_CAP ? len : CRYPTO_PREVIEW_CAP;
    const buf = ptrBuf.readByteArray(capLen);
    if (!buf) return "";
    const bytes = new Uint8Array(buf);
    const chars: number[] = [];
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) chars.push(b);
    }
    return String.fromCharCode.apply(null, chars);
  } catch (e) {
    return "";
  }
}

// hexPreview a key/iv-style buffer of unknown-but-small length (no length arg is passed to the
// *Init/AES key-setup functions). Bounded to maxLen bytes. Null-safe. Returns a [label, value]
// field pair ready for a log.detect() fields array, or null when there's nothing to preview.
function cryptoPreviewKeyMaterial(
  label: string,
  ptrBuf: NativePointer,
  maxLen: number
): [string, string] | null {
  try {
    if (!ptrBuf || ptrBuf.isNull()) return null;
    const n = maxLen > 0 ? maxLen : 16;
    return [label + " (" + n + "B)", hexPreview(ptrBuf, n)];
  } catch (e) {
    return null;
  }
}

// Inspect a produced crypto/decompression output buffer: classify magic + hex preview, then
// scan the printable content against the evasion lexicon. `source` is the caller-supplied
// identifier (e.g. "CRYPTO:EVP_DecryptUpdate"), threaded through to scan()/dumpBuffer as their
// source/tag arg exactly as the legacy `tag` local was.
function cryptoInspectOutput(
  source: string,
  ptrBuf: NativePointer,
  len: number,
  context: CpuContext
): void {
  if (!ptrBuf || ptrBuf.isNull() || len <= 0) return;

  const previewLen = len < CRYPTO_PREVIEW_CAP ? len : CRYPTO_PREVIEW_CAP;

  // payloadMagic reads 4 leading bytes; only classify once at least 4 bytes were produced so
  // we never inspect past the freshly-written region.
  let magic: ReturnType<typeof payloadMagic> = null;
  if (len >= 4) {
    try {
      magic = payloadMagic(ptrBuf);
    } catch (e) {}
  }

  // A recognized payload magic (dex/cdex/elf/zip) coming straight out of a decrypt/decompress
  // is itself a strong second-stage indicator, so surface it even without a lexicon hit.
  const signature = "cryptomagic|" + source + "|" + len + "|" + (magic || "");
  if (magic && !hasSeen(signature)) {
    markSeen(signature);
    let hex = "";
    try {
      hex = hexPreview(ptrBuf, previewLen);
    } catch (e) {}
    log.detect(
      TAG,
      source + " produced " + len + " bytes; payload magic=" + magic,
      [["Hex", hex]],
      formatBacktrace(getNativeBacktrace(context))
    );
  }

  try {
    dumpBuffer(source, ptrBuf, len);
  } catch (e) {}

  const scanStr = cryptoReadForScan(ptrBuf, len);
  if (scanStr) {
    scan(source, scanStr, () => getNativeBacktrace(context));
  }
}

const mod: DecloakerModule = {
  id: "crypto-native",
  tag: TAG,
  description:
    "Hooks BoringSSL EVP/AES and zlib inflate/uncompress to observe decrypted/decompressed output",
  enabledByDefault: true,
  install() {
    // ---- BoringSSL EVP *Update: decrypt/encrypt/cipher block updates ----
    // Signature: int EVP_(De|En|)cryptUpdate(ctx, out, int *outlen, in, inlen)
    //   out=args[1], outlen ptr=args[2], in=args[3], inlen=args[4]
    // The PLAINTEXT (for decrypt) or output lands in `out`; its true length is *outlen, valid
    // only AFTER the call. Capture out + outlen ptr on enter, read *outlen bytes on leave.
    ["EVP_DecryptUpdate", "EVP_EncryptUpdate", "EVP_CipherUpdate"].forEach((fn) => {
      const p = getExportSafe("libcrypto.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.outPtr = args[1];
            this.outLenPtr = args[2];
            // this.context is the Interceptor CpuContext; save it for the onLeave backtrace.
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip) return;
            if (retval.toInt32() !== 1) return; // BoringSSL returns 1 on success
            let outLen = 0;
            try {
              if (this.outLenPtr && !this.outLenPtr.isNull()) {
                outLen = this.outLenPtr.readInt();
              }
            } catch (e) {
              return;
            }
            if (outLen > 0) {
              cryptoInspectOutput("CRYPTO:" + fn, this.outPtr, outLen, this.ctx);
            }
          },
        });
        log.setup(TAG, "Hooked Native Crypto: " + fn + " (libcrypto.so)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- BoringSSL EVP *Final_ex: flush the last (padded) block ----
    // Signature: int EVP_(De|En|)cryptFinal_ex(ctx, out, int *outlen)
    //   out=args[1], outlen ptr=args[2]. Same capture-on-enter / read-on-leave pattern.
    ["EVP_DecryptFinal_ex", "EVP_EncryptFinal_ex", "EVP_CipherFinal_ex"].forEach((fn) => {
      const p = getExportSafe("libcrypto.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.outPtr = args[1];
            this.outLenPtr = args[2];
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip) return;
            if (retval.toInt32() !== 1) return;
            let outLen = 0;
            try {
              if (this.outLenPtr && !this.outLenPtr.isNull()) {
                outLen = this.outLenPtr.readInt();
              }
            } catch (e) {
              return;
            }
            if (outLen > 0) {
              cryptoInspectOutput("CRYPTO:" + fn, this.outPtr, outLen, this.ctx);
            }
          },
        });
        log.setup(TAG, "Hooked Native Crypto: " + fn + " (libcrypto.so)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- BoringSSL EVP *Init_ex: capture key + iv material ----
    // Signature: int EVP_(De|En|)cryptInit_ex(ctx, const EVP_CIPHER *cipher, ENGINE *impl,
    //                                         const unsigned char *key, const unsigned char *iv)
    //   cipher=args[1], key=args[3], iv=args[4]. No key/iv length is passed, so we preview a
    //   fixed cap: 32 bytes covers up to AES-256 keys, 16 bytes covers a standard IV/GCM nonce.
    //   Includes EVP_CipherInit_ex (same signature) to match the Cipher* Update/Final coverage.
    ["EVP_DecryptInit_ex", "EVP_EncryptInit_ex", "EVP_CipherInit_ex"].forEach((fn) => {
      const p = getExportSafe("libcrypto.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const cipherPtr = args[1];
            const keyPtr = args[3];
            const ivPtr = args[4];
            // Callers may pass key/iv as NULL on a first-init/second-init split; the
            // preview helper is null-safe and simply emits nothing for a NULL buffer.
            const fields: [string, string][] = [];
            const keyField = cryptoPreviewKeyMaterial("key", keyPtr, 32);
            if (keyField) fields.push(keyField);
            const ivField = cryptoPreviewKeyMaterial("iv", ivPtr, 16);
            if (ivField) fields.push(ivField);
            const ctx = this.context;
            log.detect(
              TAG,
              fn + " (cipher=" + cipherPtr + ")",
              fields,
              formatBacktrace(getNativeBacktrace(ctx))
            );
          },
        });
        log.setup(TAG, "Hooked Native Crypto: " + fn + " (libcrypto.so)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- Low-level AES key schedule setup ----
    // Signature: int AES_set_(en|de)crypt_key(const unsigned char *key, int bits, AES_KEY *out)
    //   key=args[0], bits=args[1]. Preview bits/8 key bytes (capped at 32B = AES-256).
    ["AES_set_encrypt_key", "AES_set_decrypt_key"].forEach((fn) => {
      const p = getExportSafe("libcrypto.so", fn);
      if (!p) return;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) return;
            const keyPtr = args[0];
            let bits = 0;
            try {
              bits = args[1].toInt32();
            } catch (e) {}
            let keyBytes = bits > 0 ? bits / 8 : 32;
            if (keyBytes > 32) keyBytes = 32;
            const fields: [string, string][] = [];
            const keyField = cryptoPreviewKeyMaterial("aes_key", keyPtr, keyBytes);
            if (keyField) fields.push(keyField);
            const ctx = this.context;
            log.detect(
              TAG,
              fn + " (bits=" + bits + ")",
              fields,
              formatBacktrace(getNativeBacktrace(ctx))
            );
          },
        });
        log.setup(TAG, "Hooked Native Crypto: " + fn + " (libcrypto.so)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook " + fn + ": " + e.message);
      }
    });

    // ---- zlib inflate: streaming decompression ----
    // Signature: int inflate(z_streamp strm, int flush). The decompressed bytes are written to
    // strm->next_out; the amount produced = (avail_out before) - (avail_out after). The z_stream
    // layout is { Bytef* next_in; uInt avail_in; uLong total_in; Bytef* next_out; uInt avail_out; ... }.
    // On LP64 (uLong/ptr = 8): next_in@0, avail_in@8, a 4-byte pad, total_in@16, next_out@24,
    // avail_out@32. On ILP32 (all fields 4 bytes): next_out@12, avail_out@16. We snapshot next_out +
    // avail_out on enter and diff avail_out on leave to locate exactly the freshly-produced window.
    // Struct reads are wrapped in try/catch so a layout mismatch degrades to a skip, not a crash.
    (function () {
      let p = getExportSafe("libz.so", "inflate");
      if (!p) p = getExportSafe("libc.so", "inflate"); // some ROMs fold zlib into libc
      if (!p) return;
      const wide = Process.pointerSize === 8;
      const NEXT_OUT_OFF = wide ? 24 : 12;
      const AVAIL_OUT_OFF = wide ? 32 : 16;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.strm = args[0];
            this.startOut = null;
            this.availBefore = 0;
            this.ctx = this.context;
            try {
              if (this.strm && !this.strm.isNull()) {
                this.startOut = this.strm.add(NEXT_OUT_OFF).readPointer();
                this.availBefore = this.strm.add(AVAIL_OUT_OFF).readU32();
              } else {
                this.skip = true;
              }
            } catch (e) {
              this.skip = true;
            }
          },
          onLeave: function (this: IC, retval) {
            if (this.skip || !this.startOut || this.startOut.isNull()) return;
            // inflate returns Z_OK(0) or Z_STREAM_END(1) on progress; negatives are errors.
            if (retval.toInt32() < 0) return;
            let availAfter = 0;
            try {
              availAfter = this.strm.add(AVAIL_OUT_OFF).readU32();
            } catch (e) {
              return;
            }
            const produced = this.availBefore - availAfter;
            // inflate fires on ALL framework decompression (PNG/asset/APK) - an inherently
            // hot path. Content-gate to real payloads (dex/elf/zip magic) or when dumping,
            // so ordinary decompression pays only a 4-byte magic sniff, not a full inspect.
            if (produced > 0 && (config.dumpPayloads || payloadMagic(this.startOut) !== null)) {
              cryptoInspectOutput("CRYPTO:inflate", this.startOut, produced, this.ctx);
            }
          },
        });
        log.setup(TAG, "Hooked Native Crypto: inflate (libz.so)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook inflate: " + e.message);
      }
    })();

    // ---- zlib uncompress: one-shot decompression ----
    // Signature: int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
    //   dest=args[0], destLen ptr=args[1]. On success *destLen holds the decompressed size; read
    //   it on leave and inspect dest. uLongf is unsigned long: 8 bytes on LP64, 4 bytes on ILP32.
    (function () {
      let p = getExportSafe("libz.so", "uncompress");
      if (!p) p = getExportSafe("libc.so", "uncompress");
      if (!p) return;
      const wide = Process.pointerSize === 8;
      try {
        Interceptor.attach(p, {
          onEnter: function (this: IC, args) {
            if (!isTargetCaller(this.returnAddress)) {
              this.skip = true;
              return;
            }
            this.skip = false;
            this.destPtr = args[0];
            this.destLenPtr = args[1];
            this.ctx = this.context;
          },
          onLeave: function (this: IC, retval) {
            if (this.skip) return;
            if (retval.toInt32() !== 0) return; // Z_OK == 0
            let destLen = 0;
            try {
              if (this.destLenPtr && !this.destLenPtr.isNull()) {
                destLen = wide ? this.destLenPtr.readU64().toNumber() : this.destLenPtr.readU32();
              }
            } catch (e) {
              return;
            }
            // Same hot-path gate as inflate: only inspect decompressed output that carries
            // a payload magic (or when dumping is on).
            if (destLen > 0 && (config.dumpPayloads || payloadMagic(this.destPtr) !== null)) {
              cryptoInspectOutput("CRYPTO:uncompress", this.destPtr, destLen, this.ctx);
            }
          },
        });
        log.setup(TAG, "Hooked Native Crypto: uncompress (libz.so)");
      } catch (e: any) {
        log.warn(TAG, "Failed to hook uncompress: " + e.message);
      }
    })();

    log.setup(TAG, "Native crypto/zlib hooks installed (libcrypto.so, libz.so)");
  },
};

export default mod;
