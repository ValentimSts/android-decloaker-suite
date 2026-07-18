import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: ["tests/setup.ts"],
    include: ["tests/**/*.test.ts"],
    clearMocks: true,
  },
  resolve: {
    alias: {
      // The real package executes GumJS-only top-level code on import (see
      // tests/stubs/frida-java-bridge.ts) - swap in a trivial stand-in so
      // agent code that imports "../core/java" can be unit-tested under
      // Node. Does not affect the real `pnpm run build` (frida-compile),
      // which bundles the genuine dependency.
      "frida-java-bridge": path.resolve(__dirname, "tests/stubs/frida-java-bridge.ts"),
    },
  },
});
