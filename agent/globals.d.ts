// Frida's GumJS runtime provides `console`, but @types/frida-gum does not
// declare it. We declare only this - pulling in @types/node would also add
// Node-only globals (Buffer, process, require) that the Frida runtime lacks.
declare const console: {
  log(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
  debug(...args: unknown[]): void;
};
