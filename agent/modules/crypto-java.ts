// Ported from legacy decloaker.js hookCryptoJava (lines 2640-3232).
//
// Java JCA crypto hooks for key / IV / plaintext recovery. Purely observational
// (no active-bypass branch exists in the source): we hook Cipher init/doFinal,
// SecretKeySpec / IvParameterSpec / GCMParameterSpec construction, both Base64
// decoders, Inflater / GZIPInputStream decompression, Mac init/doFinal, and
// MessageDigest update/digest. Decrypted plaintext is decoded and run through
// scan() against the shared evasion lexicon, raw key/IV/nonce captures are
// deduped, and a native copy of a decrypted output is handed to dumpBuffer only
// when it carries a recognizable dex/elf/zip magic OR config.dumpPayloads is on.
//
// The jbytes* byte[] helpers are the shared implementations from core/java (they
// honor config.truncateHex internally); dumpBuffer/payloadMagic honor
// config.dumpPayloads. Java .implementation bodies are classic function
// expressions (frida-java-bridge rebinds `this` per call) with `this`/params
// typed `any` to satisfy noImplicitAny.

import { config } from "../config";
import { C, log } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { hexPreview, payloadMagic, dumpBuffer } from "../core/memory";
import { scan } from "../filters/matcher";
import { Java, withJava, jbytesToHex, jbytesToPrintable, jbytesToNative, jbytesSlice } from "../core/java";
import type { DecloakerModule } from "../types";

const TAG = "CRYPTO";

const mod: DecloakerModule = {
  id: "crypto-java",
  tag: TAG,
  description: "Hooks JCA Cipher/SecretKeySpec/IV/Base64/Inflater/Mac/MessageDigest to recover keys, IVs, and decrypted plaintext",
  enabledByDefault: true,
  requires: "java",
  install() {
    // Belt-and-suspenders: the dispatcher already gates this module on
    // Java.available via `requires: "java"`, but the legacy script checked here
    // too and we keep behavior identical.
    if (!Java.available) {
      log.warn(TAG, "Java is not available. Skipping JCA crypto hooks.");
      return;
    }

    withJava(function () {
      // Gating note: these are Java-layer JCA hooks, NOT hot native functions, so
      // isTargetCaller / PROT_EXEC-style native gating does not apply. Output
      // volume is bounded four ways instead: hex previews are capped (jbytesToHex
      // maxLen), decoded plaintext is run through the shared scan() lexicon (only
      // target-string hits print), raw key/IV/nonce capture is deduped via
      // markSeen, and the payload-dump path (native copy + [DUMP] line) only runs
      // when the output carries a recognizable dex/elf/zip magic OR dumpPayloads
      // is on - so a tight per-message crypto loop over benign ciphertext does not
      // emit a line per doFinal.

      const HEX_CAP = 512; // max bytes rendered as hex for payloads
      const PLAIN_CAP = 4096; // max bytes decoded for lexicon matching
      const DUMP_CAP = 4 * 1024 * 1024; // max bytes copied to native for magic-sniff / dump

      // Sniff a decrypted output byte[] for a dex/elf/zip payload and, only then
      // (or when dumpPayloads is on), hand a native copy to the shared dumpBuffer.
      function sniffAndMaybeDump(tag: string, jbytes: any, outLen: number): void {
        try {
          if (outLen <= 0) return;
          const native = jbytesToNative(jbytes, DUMP_CAP);
          if (!native) return;
          // Only emit / dump when it looks like a real payload, unless dumping is forced on.
          if (config.dumpPayloads || payloadMagic(native.ptr) !== null) {
            // dumpBuffer dedups on the buffer POINTER, but jbytesToNative allocates
            // a fresh pointer every call, so identical decrypted payloads would
            // re-dump on every doFinal. Dedup on stable content first.
            const csig = "cryptodump|" + tag + "|" + native.len + "|" + hexPreview(native.ptr, 16);
            if (!hasSeen(csig)) {
              markSeen(csig);
              dumpBuffer(tag, native.ptr, native.len);
            }
          }
        } catch (e) {}
      }

      // ---- javax.crypto.Cipher (doFinal + init) ----
      try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const CIPHER_STATE_MAP: Record<string, { key: string; iv: string }> = {}; // Key & IV per cipher instance

        // Cipher.init: opmode + key + optional params. Capture the Key and IV here
        // to print them later during doFinal.
        try {
          const opName = function (op: any): string {
            // Cipher.ENCRYPT_MODE=1, DECRYPT_MODE=2, WRAP=3, UNWRAP=4
            return op === 1 ? "ENCRYPT" : op === 2 ? "DECRYPT" :
              op === 3 ? "WRAP" : op === 4 ? "UNWRAP" : ("MODE_" + op);
          };
          Cipher.init.overloads.forEach(function (ov: any) {
            ov.implementation = function (this: any) {
              try {
                const op = arguments.length > 0 ? arguments[0] : -1;
                let algo = "";
                try { algo = this.getAlgorithm(); } catch (e) {}
                const sig = "cipher.init|" + algo + "|" + op;
                if (!hasSeen(sig)) {
                  markSeen(sig);
                  console.log("\n" + C.PURPLE + "[!] [CRYPTO] Cipher.init(" + opName(op) +
                    ") algorithm=" + algo + C.RESET);
                }
              } catch (e) {}

              const ret = ov.apply(this, arguments);

              // Capture Key and IV state after init succeeds
              try {
                const hash = this.hashCode();
                let keyHex = "[Unknown/Unexportable]";
                let ivHex = "[None]";

                // Extract Key
                if (arguments.length > 1 && arguments[1] !== null) {
                  const keyObj = Java.cast(arguments[1], Java.use("java.security.Key"));
                  const encoded = keyObj.getEncoded();
                  if (encoded) keyHex = jbytesToHex(encoded, HEX_CAP);
                }

                // Extract IV
                const ivBytes = this.getIV();
                if (ivBytes) ivHex = jbytesToHex(ivBytes, HEX_CAP);

                CIPHER_STATE_MAP[hash] = { key: keyHex, iv: ivHex };
              } catch (e) {}

              return ret;
            };
          });
        } catch (e: any) {
          log.warn(TAG, "Could not hook Cipher.init: " + e.message);
        }

        // Cipher.doFinal (all overloads): extract the input payload and retrieve
        // the saved Key/IV state.
        try {
          Cipher.doFinal.overloads.forEach(function (ov: any) {
            ov.implementation = function (this: any) {
              // Describe the first byte[] argument (input ciphertext/plaintext).
              let inLen = -1;
              let inHex = "[Empty]";
              try {
                for (let a = 0; a < arguments.length; a++) {
                  const arg = arguments[a];
                  if (arg !== null && arg !== undefined && typeof arg === "object" &&
                    typeof arg.length === "number") {
                    inLen = arg.length;
                    inHex = jbytesToHex(arg, HEX_CAP);
                    break;
                  }
                }
              } catch (e) {}

              const out = ov.apply(this, arguments);

              try {
                let algo = "";
                try { algo = this.getAlgorithm(); } catch (e) {}

                // Retrieve saved state (Key/IV) for this exact cipher
                let state: { key: string; iv: string } = { key: "[Unknown]", iv: "[Unknown]" };
                try {
                  const hash = this.hashCode();
                  if (CIPHER_STATE_MAP[hash]) state = CIPHER_STATE_MAP[hash];
                } catch (e) {}

                const isBytes = (out !== null && out !== undefined &&
                  typeof out === "object" && typeof out.length === "number");
                const outLen = isBytes ? out.length : -1;

                console.log("\n" + C.CYAN + "[!] [CRYPTO] Cipher.doFinal algorithm=" + algo +
                  " in=" + (inLen >= 0 ? inLen : "?") + "B out=" +
                  (outLen >= 0 ? outLen : "?") + "B" + C.RESET);

                if (isBytes && outLen > 0) {
                  const plain = jbytesToPrintable(out, PLAIN_CAP);
                  const hex = jbytesToHex(out, HEX_CAP);

                  if (plain) {
                    // Print the full context before the green plaintext
                    console.log(C.YELLOW + "    -> [Decryption Parameters]" + C.RESET);
                    console.log(C.YELLOW + "       Algorithm : " + algo + C.RESET);
                    console.log(C.YELLOW + "       Key (Hex) : " + state.key + C.RESET);
                    console.log(C.YELLOW + "       IV  (Hex) : " + state.iv + C.RESET);
                    console.log(C.YELLOW + "       Input/Enc : " + inHex + C.RESET);
                    console.log(C.GREEN + "    -> Plaintext : " + plain + C.RESET);
                  } else {
                    // Fallback for binary payloads
                    console.log(C.YELLOW + "    -> Output hex: " + hex + C.RESET);
                  }

                  if (plain) scan("Cipher.doFinal output", plain);
                  sniffAndMaybeDump("cipher_doFinal_" +
                    String(algo).replace(/[^A-Za-z0-9]/g, "_"), out, outLen);
                }
              } catch (e) {}
              return out;
            };
          });
        } catch (e: any) {
          log.warn(TAG, "Could not hook Cipher.doFinal: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG, "Could not use javax.crypto.Cipher: " + e.message);
      }

      // ---- javax.crypto.spec.SecretKeySpec: CAPTURE raw key bytes ----
      // Where the actual symmetric key material is constructed. Capture byte[] key + algorithm.
      try {
        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overloads.forEach(function (ov: any) {
          ov.implementation = function (this: any) {
            try {
              // Overloads: (byte[] key, String algo) or (byte[] key, int off, int len, String algo).
              // For the offset/length form, hex ONLY the real [off, off+len) key slice.
              const algo = arguments.length > 0 ? arguments[arguments.length - 1] : "";
              const keySrc = (arguments.length === 4)
                ? jbytesSlice(arguments[0], arguments[1], arguments[2], HEX_CAP)
                : (arguments.length > 0 ? arguments[0] : null);
              const hex = jbytesToHex(keySrc, HEX_CAP);
              const sig = "seckey|" + algo + "|" + hex;
              if (!hasSeen(sig)) {
                markSeen(sig);
                console.log("\n" + C.RED + "[!] [CRYPTO KEY] SecretKeySpec algorithm=" +
                  algo + C.RESET);
                console.log(C.YELLOW + "    -> Key hex: " + hex + C.RESET);
              }
            } catch (e) {}
            return ov.apply(this, arguments);
          };
        });
      } catch (e: any) {
        log.warn(TAG, "Could not use SecretKeySpec: " + e.message);
      }

      // ---- javax.crypto.spec.IvParameterSpec: CAPTURE IV/nonce ----
      try {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overloads.forEach(function (ov: any) {
          ov.implementation = function (this: any) {
            try {
              // (byte[] iv) or (byte[] iv, int off, int len) - slice for the offset form.
              const ivSrc = (arguments.length === 3)
                ? jbytesSlice(arguments[0], arguments[1], arguments[2], HEX_CAP)
                : (arguments.length > 0 ? arguments[0] : null);
              const hex = jbytesToHex(ivSrc, HEX_CAP);
              const sig = "iv|" + hex;
              if (!hasSeen(sig)) {
                markSeen(sig);
                console.log("\n" + C.PURPLE + "[!] [CRYPTO IV] IvParameterSpec" + C.RESET);
                console.log(C.YELLOW + "    -> IV hex: " + hex + C.RESET);
              }
            } catch (e) {}
            return ov.apply(this, arguments);
          };
        });
      } catch (e: any) {
        log.warn(TAG, "Could not use IvParameterSpec: " + e.message);
      }

      // ---- javax.crypto.spec.GCMParameterSpec: CAPTURE AEAD nonce ----
      try {
        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        GCMParameterSpec.$init.overloads.forEach(function (ov: any) {
          ov.implementation = function (this: any) {
            try {
              // (int tLen, byte[] src) or (int tLen, byte[] src, int off, int len)
              const tLen = arguments.length > 0 ? arguments[0] : -1;
              const nonceSrc = (arguments.length === 4)
                ? jbytesSlice(arguments[1], arguments[2], arguments[3], HEX_CAP)
                : (arguments.length > 1 ? arguments[1] : null);
              const hex = jbytesToHex(nonceSrc, HEX_CAP);
              const sig = "gcm|" + tLen + "|" + hex;
              if (!hasSeen(sig)) {
                markSeen(sig);
                console.log("\n" + C.PURPLE + "[!] [CRYPTO IV] GCMParameterSpec tagLenBits=" +
                  tLen + C.RESET);
                console.log(C.YELLOW + "    -> Nonce hex: " + hex + C.RESET);
              }
            } catch (e) {}
            return ov.apply(this, arguments);
          };
        });
      } catch (e: any) {
        log.warn(TAG, "Could not use GCMParameterSpec: " + e.message);
      }

      // ---- java.util.Base64$Decoder.decode: input + output (API 26+) ----
      try {
        const B64Decoder = Java.use("java.util.Base64$Decoder");
        B64Decoder.decode.overloads.forEach(function (ov: any) {
          ov.implementation = function (this: any) {
            const out = ov.apply(this, arguments);
            try {
              const inArg = arguments.length > 0 ? arguments[0] : null;
              let inDesc = "";
              if (typeof inArg === "string") {
                inDesc = inArg.length + " chars";
                scan("Base64.Decoder input", inArg);
              } else if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                typeof inArg.length === "number") {
                inDesc = inArg.length + "B";
              }
              const isBytes = (out !== null && out !== undefined &&
                typeof out === "object" && typeof out.length === "number");
              if (isBytes) {
                console.log("\n" + C.CYAN + "[!] [CRYPTO] Base64.Decoder.decode in=" +
                  inDesc + " out=" + out.length + "B" + C.RESET);
                console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(out, HEX_CAP) + C.RESET);
                const plain = jbytesToPrintable(out, PLAIN_CAP);
                if (plain) scan("Base64.Decoder output", plain);
              }
            } catch (e) {}
            return out;
          };
        });
      } catch (e: any) {
        log.warn(TAG, "Could not use java.util.Base64$Decoder: " + e.message);
      }

      // ---- android.util.Base64.decode (static): input + output ----
      try {
        const AndroidB64 = Java.use("android.util.Base64");
        AndroidB64.decode.overloads.forEach(function (ov: any) {
          ov.implementation = function (this: any) {
            const out = ov.apply(this, arguments);
            try {
              const inArg = arguments.length > 0 ? arguments[0] : null;
              let inDesc = "";
              if (typeof inArg === "string") {
                inDesc = inArg.length + " chars";
                scan("android.util.Base64 input", inArg);
              } else if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                typeof inArg.length === "number") {
                inDesc = inArg.length + "B";
              }
              const isBytes = (out !== null && out !== undefined &&
                typeof out === "object" && typeof out.length === "number");
              if (isBytes) {
                console.log("\n" + C.CYAN + "[!] [CRYPTO] android.util.Base64.decode in=" +
                  inDesc + " out=" + out.length + "B" + C.RESET);
                console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(out, HEX_CAP) + C.RESET);
                const plain = jbytesToPrintable(out, PLAIN_CAP);
                if (plain) scan("android.util.Base64 output", plain);
              }
            } catch (e) {}
            return out;
          };
        });
      } catch (e: any) {
        log.warn(TAG, "Could not use android.util.Base64: " + e.message);
      }

      // ---- java.util.zip.Inflater.inflate: decompressed output ----
      // inflate(byte[] out [,int off,int len]) returns bytes written INTO the supplied output
      // buffer. Read back the written slice to recover the decompressed (deflate-packed) payload.
      // The inflate(ByteBuffer) overload has no .length arg and is skipped by the isBytes guard.
      try {
        const Inflater = Java.use("java.util.zip.Inflater");
        Inflater.inflate.overloads.forEach(function (ov: any) {
          ov.implementation = function (this: any) {
            const n = ov.apply(this, arguments);
            try {
              const buf = arguments.length > 0 ? arguments[0] : null;
              const off = (arguments.length > 2 && typeof arguments[1] === "number") ? arguments[1] : 0;
              const isBytes = (buf !== null && buf !== undefined &&
                typeof buf === "object" && typeof buf.length === "number");
              const written = (typeof n === "number") ? n : 0;
              if (isBytes && written > 0) {
                const slice = jbytesSlice(buf, off, written, PLAIN_CAP);
                if (slice.length > 0) {
                  // Console header/hex output is intentionally muted (legacy commented it
                  // out to avoid a console flood); we still scan the slice for threats.
                  const plain = jbytesToPrintable(slice, PLAIN_CAP);
                  if (plain) scan("Inflater.inflate output", plain);
                }
              }
            } catch (e) {}
            return n;
          };
        });
      } catch (e: any) {
        log.warn(TAG, "Could not use java.util.zip.Inflater: " + e.message);
      }

      // ---- java.util.zip.GZIPInputStream.read: decompressed output ----
      // read(byte[] b, int off, int len) returns bytes decompressed into b. Read back the slice.
      // Capture the original overload; calling this.read(...) inside .implementation would recurse.
      try {
        const GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
        const gzipReadOv = GZIPInputStream.read.overload("[B", "int", "int");
        gzipReadOv.implementation = function (this: any, b: any, off: any, len: any) {
          const n = gzipReadOv.call(this, b, off, len);
          try {
            const isBytes = (b !== null && b !== undefined &&
              typeof b === "object" && typeof b.length === "number");
            if (typeof n === "number" && n > 0 && isBytes) {
              const slice = jbytesSlice(b, off, n, PLAIN_CAP);
              if (slice.length > 0) {
                console.log("\n" + C.CYAN + "[!] [CRYPTO] GZIPInputStream.read decompressed=" +
                  n + "B" + C.RESET);
                console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(slice, HEX_CAP) + C.RESET);
                const plain = jbytesToPrintable(slice, PLAIN_CAP);
                if (plain) scan("GZIPInputStream.read output", plain);
              }
            }
          } catch (e) {}
          return n;
        };
      } catch (e: any) {
        log.warn(TAG, "Could not hook GZIPInputStream.read: " + e.message);
      }

      // ---- javax.crypto.Mac.init + doFinal: HMAC key + message ----
      try {
        const Mac = Java.use("javax.crypto.Mac");
        try {
          Mac.init.overloads.forEach(function (ov: any) {
            ov.implementation = function (this: any) {
              try {
                let algo = "";
                try { algo = this.getAlgorithm(); } catch (e) {}
                // arg0 is a Key; a SecretKeySpec's raw bytes are captured on construction.
                const sig = "mac.init|" + algo;
                if (!hasSeen(sig)) {
                  markSeen(sig);
                  console.log("\n" + C.PURPLE + "[!] [CRYPTO] Mac.init algorithm=" +
                    algo + C.RESET);
                }
              } catch (e) {}
              return ov.apply(this, arguments);
            };
          });
        } catch (e: any) {
          log.warn(TAG, "Could not hook Mac.init: " + e.message);
        }
        try {
          Mac.doFinal.overloads.forEach(function (ov: any) {
            ov.implementation = function (this: any) {
              const inArg = arguments.length > 0 ? arguments[0] : null;
              const inLen = (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                typeof inArg.length === "number") ? inArg.length : -1;
              const out = ov.apply(this, arguments);
              try {
                let algo = "";
                try { algo = this.getAlgorithm(); } catch (e) {}
                const isBytes = (out !== null && out !== undefined &&
                  typeof out === "object" && typeof out.length === "number");
                console.log("\n" + C.CYAN + "[!] [CRYPTO] Mac.doFinal(" + algo + ") msg=" +
                  (inLen >= 0 ? inLen + "B" : "?") + " mac=" +
                  (isBytes ? out.length + "B" : "?") + C.RESET);
                if (inLen > 0) {
                  const msgPlain = jbytesToPrintable(inArg, PLAIN_CAP);
                  if (msgPlain) scan("Mac.doFinal message", msgPlain);
                }
                if (isBytes && out.length > 0) {
                  console.log(C.YELLOW + "    -> MAC hex: " + jbytesToHex(out, HEX_CAP) + C.RESET);
                }
              } catch (e) {}
              return out;
            };
          });
        } catch (e: any) {
          log.warn(TAG, "Could not hook Mac.doFinal: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG, "Could not use javax.crypto.Mac: " + e.message);
      }

      // ---- java.security.MessageDigest.update + digest: hashed input ----
      try {
        const MessageDigest = Java.use("java.security.MessageDigest");
        try {
          MessageDigest.update.overloads.forEach(function (ov: any) {
            ov.implementation = function (this: any) {
              try {
                const inArg = arguments.length > 0 ? arguments[0] : null;
                if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                  typeof inArg.length === "number" && inArg.length > 0) {
                  const plain = jbytesToPrintable(inArg, PLAIN_CAP);
                  if (plain) scan("MessageDigest.update input", plain);
                }
              } catch (e) {}
              return ov.apply(this, arguments);
            };
          });
        } catch (e: any) {
          log.warn(TAG, "Could not hook MessageDigest.update: " + e.message);
        }
        try {
          MessageDigest.digest.overloads.forEach(function (ov: any) {
            ov.implementation = function (this: any) {
              // Only the single-arg digest(byte[] input) overload feeds data via arg0.
              // In digest(byte[] buf, int offset, int len) arg0 is the OUTPUT buffer, so
              // scanning it as input would misreport stale/output bytes - gate on arity 1.
              try {
                const inArg = arguments.length === 1 ? arguments[0] : null;
                if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                  typeof inArg.length === "number" && inArg.length > 0) {
                  const plain = jbytesToPrintable(inArg, PLAIN_CAP);
                  if (plain) scan("MessageDigest.digest input", plain);
                }
              } catch (e) {}
              const out = ov.apply(this, arguments);
              try {
                let algo = "";
                try { algo = this.getAlgorithm(); } catch (e) {}
                const isBytes = (out !== null && out !== undefined &&
                  typeof out === "object" && typeof out.length === "number");
                if (isBytes && out.length > 0) {
                  console.log("\n" + C.CYAN + "[!] [CRYPTO] MessageDigest.digest(" + algo +
                    ") -> " + jbytesToHex(out, HEX_CAP) + C.RESET);
                }
              } catch (e) {}
              return out;
            };
          });
        } catch (e: any) {
          log.warn(TAG, "Could not hook MessageDigest.digest: " + e.message);
        }
      } catch (e: any) {
        log.warn(TAG, "Could not use java.security.MessageDigest: " + e.message);
      }

      log.setup(TAG, "Hooked Java JCA crypto (Cipher, SecretKeySpec, Iv/GCM, Base64, Inflater/GZIP, Mac, MessageDigest)");
    });
  },
};

export default mod;
