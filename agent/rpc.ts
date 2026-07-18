// Live RPC toggles, exposed to the Frida host as rpc.exports.
//
// addtarget/cleartargets/setfulltrace/setbypass/setdump/setquiet/settruncatehex
// are a behavior-preserving port of the legacy decloaker.js rpc.exports block
// (lines 361-394): each mutates the same `config` field the legacy top-level
// var did, with the same push-if-new / always-vs-gated printing behavior. The
// legacy file wrote ad-hoc `console.log(C.COLOR + "[mark] ..." )` calls; here
// each is replaced with the `log.<level>` call whose mark/color/gating best
// matches that call site:
//   - addtarget "not loaded" warning / cleartargets confirmation -> the
//     legacy GREEN "[+]"/YELLOW "[!]" lines corresponded to a hook-install
//     confirmation and a warning, i.e. log.setup (GREEN, gated by
//     config.quietSetup - same as legacy's own "[+]" console.log filter) and
//     log.warn (YELLOW, always shown).
//   - setbypass -> log.bypass ("[BYPASS]", RED, always shown - legacy's own
//     "[!]" RED line was never gated either).
//   - setdump -> log.dump ("[DUMP]", PURPLE, always shown), matching legacy.
//   - setquiet/settruncatehex -> log.info ("[*]", always shown); legacy
//     deliberately used "[*]" (not "[+]") here specifically so the
//     confirmation is visible even while quiet - log.info is never gated.
//   - setfulltrace has no confirmation, matching legacy exactly.
//
// enable/disable/enableonly/list are new: per-module toggles over the
// registry built by agent/modules/index.ts, all delegating to config.modules.

import { config } from "./config";
import { log } from "./core/logger";
import { registry } from "./modules/index";
import type { DecloakerModule } from "./types";

function findModule(id: string): DecloakerModule | undefined {
  return registry.find((m) => m.id === id);
}

// A module's flag may still be unset if this is called before installAll()
// (agent/modules/index.ts) has run its one-time seedModuleFlags() pass.
function effectiveEnabled(m: DecloakerModule): boolean {
  const v = config.modules[m.id];
  return v === undefined ? m.enabledByDefault : v;
}

rpc.exports = {
  addtarget(elfName: string) {
    if (config.targetModules.indexOf(elfName) === -1) {
      config.targetModules.push(elfName);
      if (Process.findModuleByName(elfName) === null) {
        log.warn("RPC", "'" + elfName + "' is not currently loaded in memory.");
      } else {
        log.setup("RPC", "Now exclusively analyzing module: " + elfName);
      }
    }
  },

  cleartargets() {
    config.targetModules = [];
    log.setup("RPC", "Cleared exclusive targets. Reverting to global analysis.");
  },

  setfulltrace(enabled: boolean) {
    config.fullBacktrace = !!enabled;
  },

  setbypass(enabled: boolean) {
    config.activeBypass = !!enabled;
    log.bypass("RPC", "Active Bypass Mode is now: " + (config.activeBypass ? "ENABLED" : "DISABLED"));
  },

  setdump(enabled: boolean) {
    config.dumpPayloads = !!enabled;
    log.dump(
      "RPC",
      "Payload Dumping is now: " +
        (config.dumpPayloads ? "ENABLED -> " + config.dumpDir : "DISABLED")
    );
  },

  setquiet(enabled: boolean) {
    config.quietSetup = !!enabled;
    log.info(
      "RPC",
      "Setup-log verbosity: " +
        (config.quietSetup ? "QUIET (hiding [+] setup lines)" : "verbose")
    );
  },

  settruncatehex(enabled: boolean) {
    config.truncateHex = !!enabled;
    log.info("RPC", "TRUNCATE_HEX set to: " + config.truncateHex);
  },

  enable(id: string) {
    const m = findModule(id);
    if (!m) {
      log.warn("RPC", "enable: unknown module id '" + id + "'");
      return;
    }
    config.modules[id] = true;
    log.info("RPC", "module '" + id + "' enabled");
  },

  disable(id: string) {
    const m = findModule(id);
    if (!m) {
      log.warn("RPC", "disable: unknown module id '" + id + "'");
      return;
    }
    config.modules[id] = false;
    log.info("RPC", "module '" + id + "' disabled");
  },

  enableonly(...ids: string[]) {
    const want = new Set(ids);
    const known: string[] = [];
    const unknown: string[] = [];
    for (const id of ids) {
      if (findModule(id)) known.push(id);
      else unknown.push(id);
    }
    for (const m of registry) config.modules[m.id] = want.has(m.id);
    if (unknown.length > 0) {
      log.warn("RPC", "enableonly: unknown module id(s): " + unknown.join(", "));
    }
    log.info("RPC", "modules now enabled: " + (known.length > 0 ? known.join(", ") : "(none)"));
  },

  list(): Record<string, boolean> {
    const states: Record<string, boolean> = {};
    for (const m of registry) {
      const on = effectiveEnabled(m);
      states[m.id] = on;
      log.info("RPC", m.id + " (" + m.tag + "): " + (on ? "enabled" : "disabled"));
    }
    return states;
  },
};
