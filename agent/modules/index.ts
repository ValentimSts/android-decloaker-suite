// Module registry and dispatcher.
//
// `registry` starts empty on purpose: each Phase-D task pushes its own
// DecloakerModule into it (keeping registry order == the original dispatch
// order from decloaker.js's setImmediate initializer). installAll() over an
// empty registry is a clean no-op - it still seeds flags and returns.

import type { Config, DecloakerModule } from "../types";
import { config } from "../config";
import { log } from "../core/logger";
import { Java } from "../core/java";

export const registry: DecloakerModule[] = [];

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

// One-shot environment gate. Modules that need an environment which can
// appear late (e.g. libil2cpp.so loading after process start) are
// responsible for their own retry/wait logic inside install() - this check
// only decides whether to attempt the install right now.
function envReady(m: DecloakerModule): boolean {
  if (m.requires === "java") return Java.available;
  if (m.requires === "il2cpp") return Process.findModuleByName("libil2cpp.so") !== null;
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
