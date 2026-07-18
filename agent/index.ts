/// <reference path="./globals.d.ts" />
import { config } from "./config";
import { C, log } from "./core/logger";
import { installAll } from "./modules/index";
import "./rpc";

setImmediate(() => {
  console.log(C.CYAN + "=========================================" + C.RESET);
  console.log(C.CYAN + "[*] android-decloaker-suite agent loaded" + C.RESET);
  console.log(C.CYAN + "=========================================" + C.RESET);

  log.info(
    "BANNER",
    config.activeBypass
      ? "ACTIVE_BYPASS: ENABLED - the sample's behavior is being MUTATED."
      : "ACTIVE_BYPASS: disabled (observe-only). Enable via the setbypass RPC."
  );

  for (const mod of config.targetModules) {
    if (Process.findModuleByName(mod) === null) {
      log.warn("BANNER", "Target '" + mod + "' is not currently mapped in memory.");
    } else {
      log.setup("BANNER", "Target '" + mod + "' is loaded and actively monitored.");
    }
  }

  // installAll() (agent/modules/index.ts) seeds config.modules from each
  // module's enabledByDefault, then installs every enabled module whose
  // `requires` environment gate passes right now (Java.available /
  // libil2cpp.so already mapped), each wrapped in try/catch. This is only a
  // ONE-SHOT check: a module with `requires: "il2cpp"` that is enabled but
  // whose runtime (e.g. a Unity game) has not yet mapped libil2cpp.so at this
  // point is skipped here, not retried by the dispatcher. That module's own
  // install() is expected to set up its own late-load wait/poll (see the
  // unity-il2cpp module) so a single missed check at boot does not
  // permanently disable it.
  installAll();
});
