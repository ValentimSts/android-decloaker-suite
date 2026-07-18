// Minimal stand-in for the real "frida-java-bridge" package, used ONLY under
// vitest (aliased in vitest.config.ts). The real package runs top-level code
// that reads Frida/GumJS-only globals (Process, NativePointer, ptr, ...) the
// moment it is imported, so it cannot load in plain Node - it is only ever
// meant to execute inside Frida's runtime. `agent/core/java.ts` imports the
// real package for that runtime; this stub lets modules that merely import
// core/java (without exercising real JVM behavior) be unit-tested under Node.
// The actual `pnpm run build` (frida-compile) bundles the real dependency,
// unaffected by this alias.
const Java = {
  available: false,
  perform(fn: () => void): void {
    fn();
  },
};

export default Java;
