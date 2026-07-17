// @types/frida-gum declares InvocationContext, NativePointer, CpuContext, etc.
// as AMBIENT GLOBALS (no module exports), so reference them directly - do NOT
// `import ... from "frida-gum"` (that module has no exports and fails to resolve).

export type LogLevel = "detect" | "bypass" | "dump" | "setup" | "warn" | "info";

export type TraceThunk = () => string;

/** InvocationContext plus the ad-hoc fields handlers stash on `this`. */
export type IC = InvocationContext & Record<string, any>;

export interface DecloakerModule {
  id: string;
  tag: string;
  description: string;
  enabledByDefault: boolean;
  requires?: "java" | "il2cpp";
  install(): void;
}

export interface Config {
  activeBypass: boolean;
  dumpPayloads: boolean;
  dumpDir: string;
  fullBacktrace: boolean;
  truncateHex: boolean;
  quietSetup: boolean;
  hookMemoryProtection: boolean;
  targetModules: string[];
  modules: Record<string, boolean>;
}
