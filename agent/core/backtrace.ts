import { config } from "../config";

// CpuContext / NativePointer are ambient frida-gum globals - do NOT import them.
export function getNativeBacktrace(context: CpuContext): string {
  try {
    return Thread.backtrace(context, Backtracer.FUZZY)
      .map(DebugSymbol.fromAddress)
      .join("\n    ");
  } catch (e) {
    return "";
  }
}

export function formatBacktrace(bt: string): string {
  if (!bt) return "[Native Backtrace unavailable]";
  if (config.fullBacktrace) return bt;
  const lines = bt.split("\n    ");
  if (lines.length > 5) {
    return lines.slice(0, 5).join("\n    ") + "\n    ... [TRUNCATED - set fullBacktrace to expand]";
  }
  return bt;
}

export function isTargetCaller(returnAddress: NativePointer): boolean {
  if (config.targetModules.length === 0) return true;
  const mod = Process.findModuleByAddress(returnAddress);
  if (!mod) return false;
  return config.targetModules.indexOf(mod.name) !== -1;
}
