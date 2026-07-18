// Module registry and dispatcher.
//
// registry order reproduces the original decloaker.js setImmediate dispatch
// order exactly (see the plan's "Registry order" section). installAll() walks
// it, seeds flags from each module's enabledByDefault, and installs every
// enabled module whose environment gate passes, each inside try/catch.
//
// The four modules marked (disabled) ship enabledByDefault:false - repaired
// but off; the user enables each via rpc.enable("<id>") for manual testing.

import type { Config, DecloakerModule } from "../types";
import { config } from "../config";
import { log } from "../core/logger";
import { Java } from "../core/java";

import unityIl2cpp from "./unity/unity-il2cpp";
import nativeFileIo from "./native/native-file-io";
import deepExecution from "./native/deep-execution";
import rawSyscalls from "./native/raw-syscalls";
import libraryLoading from "./native/library-loading"; // disabled
import javaNativeLoaders from "./java/java-native-loaders"; // disabled
import systemProperties from "./native/system-properties";
import javaDcl from "./java/java-dcl";
import javaEvasion from "./java/java-evasion";
import networkTraffic from "./native/network-traffic";
import stringsNative from "./native/strings-native"; // disabled
import libart from "./jni/libart";
import jniEnv from "./jni/jni-env";
import jniExtended from "./jni/jni-extended";
import artDexLoaders from "./jni/art-dex-loaders";
import fileContent from "./native/file-content";
import fsRecon from "./native/fs-recon";
import cryptoJava from "./java/crypto-java";
import cryptoNative from "./native/crypto-native";
import memoryUnpacking from "./native/memory-unpacking";
import reflection from "./java/reflection";
import antiDebugNative from "./native/anti-debug-native";
import propertyModern from "./native/property-modern";
import netC2Native from "./native/net-c2-native";
import netC2Java from "./java/net-c2-java";
import behaviorIpc from "./java/behavior-ipc";
import javaStateDebug from "./java/java-state-debug"; // disabled

export const registry: DecloakerModule[] = [
  unityIl2cpp,
  nativeFileIo,
  deepExecution,
  rawSyscalls,
  libraryLoading,
  javaNativeLoaders,
  systemProperties,
  javaDcl,
  javaEvasion,
  networkTraffic,
  stringsNative,
  libart,
  jniEnv,
  jniExtended,
  artDexLoaders,
  fileContent,
  fsRecon,
  cryptoJava,
  cryptoNative,
  memoryUnpacking,
  reflection,
  antiDebugNative,
  propertyModern,
  netC2Native,
  netC2Java,
  behaviorIpc,
  javaStateDebug,
];

// Fill config.modules[id] from each module's enabledByDefault, but only for
// ids not already set - so a toggle made before installAll() runs (or a
// re-run) is never clobbered back to the compiled-in default.
export function seedModuleFlags(): void {
  for (const m of registry) {
    if (config.modules[m.id] === undefined) config.modules[m.id] = m.enabledByDefault;
  }
}

// Pure so it is unit-testable without touching the live registry/config.
export function selectEnabled(reg: DecloakerModule[], cfg: Config): DecloakerModule[] {
  return reg.filter((m) => cfg.modules[m.id]);
}

// Environment gate for the "java" requirement only. A pure-Java module calls
// Java.use, which throws without a VM, so it is skipped until a later run sees
// Java.available. Environments that can appear LATE (libil2cpp.so mapping after
// process start) must NOT be hard-gated here: doing so would skip install()
// and thereby the module's own late-load poll. Such modules (requires:"il2cpp",
// see unity-il2cpp) fall through to `true` and always install, self-managing
// their wait/retry inside install() exactly as the legacy monolith did.
function envReady(m: DecloakerModule): boolean {
  if (m.requires === "java") return Java.available;
  return true;
}

export function installAll(): void {
  seedModuleFlags();
  for (const m of selectEnabled(registry, config)) {
    if (!envReady(m)) {
      log.warn(m.tag, "skipped: environment for '" + m.requires + "' not available");
      continue;
    }
    try {
      m.install();
      log.setup(m.tag, "installed");
    } catch (e: any) {
      log.warn(m.tag, "install failed: " + (e && e.message ? e.message : e));
    }
  }
}
