import type { Config } from "./types";

// Compile-time defaults. Mutated at runtime by rpc.ts.
// Observe-first: activeBypass defaults OFF (confirmed with the user). The
// original V28 file shipped ACTIVE_BYPASS=true, but its own comment documented
// OFF; enable at runtime via rpc.setbypass(true) to deliberately defeat cloaking.
export const config: Config = {
  activeBypass: false,
  dumpPayloads: false,
  dumpDir: "/data/local/tmp",
  fullBacktrace: false,
  truncateHex: false,
  quietSetup: true,
  hookMemoryProtection: false,
  targetModules: [],
  modules: {},
};
