// Ported from legacy decloaker.js hookUnityIL2CPP (lines 5676-5885) together with
// its module-private helpers readIl2CppByteArray / getIl2CppApi / hookIl2cppMethod /
// hookIl2cppByOffset, plus the initializer's libil2cpp.so late-load poll (lines 5909-5915).
//
// Unity games built with IL2CPP run their C# logic as native code inside libil2cpp.so,
// so the Java crypto hooks never observe it. We resolve a handful of System.* crypto
// methods through the IL2CPP metadata API (or fixed offsets when STRIPPED_MODE is on)
// and observe Base64 decoding, AES key/IV configuration, and RijndaelManagedTransform
// block decryption, dumping the captured material. Detection-only: nothing is mutated.
//
// libil2cpp.so is frequently mapped a moment after process start, so install() polls
// for it every 500ms and only wires the hooks once it appears, then clears the poll.

import { log } from "../core/logger";
import { getExportSafe, hexPreview } from "../core/memory";
import type { IC, DecloakerModule } from "../types";

const TAG = "UNITY CRYPTO";

// If dynamic resolution fails (binary completely stripped of IL2CPP metadata symbols),
// set STRIPPED_MODE = true and replace the 0x000000 placeholders in OFFSETS with the
// actual offsets from an Il2CppDumper run (dummyDlls/script.json), to hook by raw offset.
const STRIPPED_MODE = false;
const OFFSETS = {
  Convert_FromBase64String: 0x000000,
  Aes_set_Key: 0x000000,
  Aes_set_IV: 0x000000,
  TransformFinalBlock: 0x000000,
};

// Safely read a C# byte[] inside IL2CPP memory. The array header layout differs by
// pointer width: length@0x18 data@0x20 on 64-bit, length@0x0C data@0x10 on 32-bit.
// Bounded to 10MB and fault-guarded.
function readIl2CppByteArray(arrayPtr: NativePointer): ArrayBuffer | null {
  if (!arrayPtr || arrayPtr.isNull()) return null;
  const pSize = Process.pointerSize;
  const lengthOffset = pSize === 8 ? 0x18 : 0x0c;
  const dataOffset = pSize === 8 ? 0x20 : 0x10;

  try {
    const len = arrayPtr.add(lengthOffset).readU32();
    if (len > 0 && len < 1024 * 1024 * 10) {
      return arrayPtr.add(dataOffset).readByteArray(len);
    }
  } catch (e) {}
  return null;
}

// Robust API resolver: checks exports first, falls back to enumerated internal symbols.
function getIl2CppApi(name: string): NativePointer | null {
  const p = getExportSafe("libil2cpp.so", name);
  if (p) return p;

  try {
    const symbols = Process.getModuleByName("libil2cpp.so").enumerateSymbols();
    for (let i = 0; i < symbols.length; i++) {
      if (symbols[i].name === name) return symbols[i].address;
    }
  } catch (e) {}
  return null;
}

// IL2CPP dynamic method resolver: walks the loaded assemblies, finds the class by
// namespace/name, resolves the method by name + arg count, and attaches to its native
// method pointer.
function hookIl2cppMethod(
  namespaceName: string,
  className: string,
  methodName: string,
  argCount: number,
  callbacks: InvocationListenerCallbacks
): boolean {
  try {
    const p_domainGet = getIl2CppApi("il2cpp_domain_get");
    const p_domainGetAssemblies = getIl2CppApi("il2cpp_domain_get_assemblies");
    const p_assemblyGetImage = getIl2CppApi("il2cpp_assembly_get_image");
    const p_classFromName = getIl2CppApi("il2cpp_class_from_name");
    const p_classGetMethodFromName = getIl2CppApi("il2cpp_class_get_method_from_name");

    if (!p_domainGet || !p_domainGetAssemblies || !p_assemblyGetImage || !p_classFromName || !p_classGetMethodFromName) {
      throw new Error("IL2CPP APIs are completely stripped from this binary.");
    }

    const domainGet = new NativeFunction(p_domainGet, "pointer", []);
    const domainGetAssemblies = new NativeFunction(p_domainGetAssemblies, "pointer", ["pointer", "pointer"]);
    const assemblyGetImage = new NativeFunction(p_assemblyGetImage, "pointer", ["pointer"]);
    const classFromName = new NativeFunction(p_classFromName, "pointer", ["pointer", "pointer", "pointer"]);
    const classGetMethodFromName = new NativeFunction(p_classGetMethodFromName, "pointer", ["pointer", "pointer", "int"]);

    const domain = domainGet();
    const sizePtr = Memory.alloc(Process.pointerSize);
    const assemblies = domainGetAssemblies(domain, sizePtr);
    const count = sizePtr.readU32();

    for (let i = 0; i < count; i++) {
      const assembly = assemblies.add(i * Process.pointerSize).readPointer();
      const image = assemblyGetImage(assembly);

      const nsPtr = Memory.allocUtf8String(namespaceName);
      const clsPtr = Memory.allocUtf8String(className);
      const klass = classFromName(image, nsPtr, clsPtr);

      if (!klass.isNull()) {
        const methPtr = Memory.allocUtf8String(methodName);
        const method = classGetMethodFromName(klass, methPtr, argCount);
        if (!method.isNull()) {
          const methodPointer = method.readPointer();
          if (!methodPointer.isNull()) {
            Interceptor.attach(methodPointer, callbacks);
            log.setup(TAG, "Hooked C# Method: " + namespaceName + "." + className + "." + methodName);
            return true;
          }
        }
      }
    }
    log.warn(TAG, "Method not found in IL2CPP memory: " + className + "." + methodName);
  } catch (e: any) {
    log.warn(TAG, "Could not resolve IL2CPP method " + className + "." + methodName + ": " + e.message);
  }
  return false;
}

// Manual offset hooker: use this when the binary is completely stripped and STRIPPED_MODE
// is set. Hooks libil2cpp.so base + fixed offset.
function hookIl2cppByOffset(
  className: string,
  methodName: string,
  offset: number,
  callbacks: InvocationListenerCallbacks
): void {
  try {
    const il2cppBase = Process.getModuleByName("libil2cpp.so").base;
    const targetAddr = il2cppBase.add(offset);
    Interceptor.attach(targetAddr, callbacks);
    log.setup(TAG, "Hooked C# Method (by offset): " + className + "." + methodName + " @ " + targetAddr);
  } catch (e: any) {
    log.warn(TAG, "Failed to hook offset for " + className + "." + methodName + ": " + e.message);
  }
}

function hookUnityIL2CPP(): void {
  const il2cpp = Process.findModuleByName("libil2cpp.so");
  if (!il2cpp) {
    log.warn(TAG, "libil2cpp.so not loaded. Not a Unity IL2CPP game.");
    return;
  }
  log.setup(TAG, "Unity IL2CPP Engine detected. Injecting C# decloaking hooks...");

  // -------------------------------------------------------------------------
  // 1. C# BASE64 DECODING
  // -------------------------------------------------------------------------
  const b64Callbacks: ScriptInvocationListenerCallbacks = {
    onEnter: function (this: IC, args) {
      const pSize = Process.pointerSize;
      const strOffset = pSize === 8 ? 0x14 : 0x0c;
      try {
        this.b64Str = args[0].add(strOffset).readUtf16String();
      } catch (e) {
        this.b64Str = "[Error reading IL2CPP String]";
      }
    },
    onLeave: function (this: IC, retval) {
      const b64Str: string = this.b64Str;
      if (b64Str && b64Str.length > 20) {
        const fields: [string, string][] = [["Input Base64", b64Str.substring(0, 150) + "..."]];
        const rawBytes = readIl2CppByteArray(retval);
        if (rawBytes) {
          const mem = Memory.alloc(rawBytes.byteLength).writeByteArray(rawBytes);
          fields.push(["Output Bytes", hexPreview(mem, 32)]);
        }
        log.dump(TAG, "System.Convert.FromBase64String", fields);
      }
    },
  };

  if (STRIPPED_MODE) hookIl2cppByOffset("System.Convert", "FromBase64String", OFFSETS.Convert_FromBase64String, b64Callbacks);
  else hookIl2cppMethod("System", "Convert", "FromBase64String", 1, b64Callbacks);

  // -------------------------------------------------------------------------
  // 2. C# AES KEY & IV STEALERS
  // -------------------------------------------------------------------------
  const keyCallbacks: ScriptInvocationListenerCallbacks = {
    onEnter: function (this: IC, args) {
      const keyBytes = readIl2CppByteArray(args[1]);
      if (keyBytes) {
        const mem = Memory.alloc(keyBytes.byteLength).writeByteArray(keyBytes);
        log.detect(TAG, "AES Key Configured!", [["Key (Hex)", hexPreview(mem, 64)]]);
      }
    },
  };

  const ivCallbacks: ScriptInvocationListenerCallbacks = {
    onEnter: function (this: IC, args) {
      const ivBytes = readIl2CppByteArray(args[1]);
      if (ivBytes) {
        const mem = Memory.alloc(ivBytes.byteLength).writeByteArray(ivBytes);
        log.detect(TAG, "AES IV Configured!", [["IV (Hex)", hexPreview(mem, 64)]]);
      }
    },
  };

  if (STRIPPED_MODE) {
    hookIl2cppByOffset("SymmetricAlgorithm", "set_Key", OFFSETS.Aes_set_Key, keyCallbacks);
    hookIl2cppByOffset("SymmetricAlgorithm", "set_IV", OFFSETS.Aes_set_IV, ivCallbacks);
  } else {
    hookIl2cppMethod("System.Security.Cryptography", "SymmetricAlgorithm", "set_Key", 1, keyCallbacks);
    hookIl2cppMethod("System.Security.Cryptography", "SymmetricAlgorithm", "set_IV", 1, ivCallbacks);
  }

  // -------------------------------------------------------------------------
  // 3. C# BLOCK CIPHER DECRYPTION (RijndaelManagedTransform)
  // -------------------------------------------------------------------------
  const transformCallbacks: ScriptInvocationListenerCallbacks = {
    onEnter: function (this: IC, args) {
      this.inCount = args[3].toInt32();
      this.inBytes = readIl2CppByteArray(args[1]);
    },
    onLeave: function (this: IC, retval) {
      const fields: [string, string][] = [];
      const inBytes = this.inBytes;
      if (inBytes) {
        const inMem = Memory.alloc(inBytes.byteLength).writeByteArray(inBytes);
        fields.push(["Input Ciphertext", hexPreview(inMem, 32)]);
      }
      const outBytes = readIl2CppByteArray(retval);
      if (outBytes) {
        const outMem = Memory.alloc(outBytes.byteLength).writeByteArray(outBytes);
        let plainStr = "";
        const u8 = new Uint8Array(outBytes);
        for (let i = 0; i < u8.length; i++) {
          if (u8[i] >= 32 && u8[i] <= 126) plainStr += String.fromCharCode(u8[i]);
        }
        if (plainStr.length > 5) {
          fields.push(["Output Plaintext ASCII", plainStr]);
        } else {
          fields.push(["Output Plaintext Hex", hexPreview(outMem, 64)]);
        }
      }
      log.dump(TAG, "AES TransformFinalBlock Executed", fields);
    },
  };

  if (STRIPPED_MODE) hookIl2cppByOffset("RijndaelManagedTransform", "TransformFinalBlock", OFFSETS.TransformFinalBlock, transformCallbacks);
  else hookIl2cppMethod("System.Security.Cryptography", "RijndaelManagedTransform", "TransformFinalBlock", 3, transformCallbacks);
}

const mod: DecloakerModule = {
  id: "unity-il2cpp",
  tag: TAG,
  description: "Hooks Unity IL2CPP C# crypto (Convert.FromBase64String, AES key/IV, RijndaelManagedTransform) to observe decryption",
  enabledByDefault: true,
  requires: "il2cpp",
  install() {
    // Poll for libil2cpp.so, which the game often maps slightly after launch. Once it
    // appears, stop polling and wire the C# decloaking hooks.
    const unityWait = setInterval(function () {
      if (Process.findModuleByName("libil2cpp.so")) {
        clearInterval(unityWait);
        hookUnityIL2CPP();
      }
    }, 500);
  },
};

export default mod;
