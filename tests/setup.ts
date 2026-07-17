// Minimal stand-ins so pure-logic modules that touch a few Frida globals or
// NativePointer methods can be unit-tested under Node. Hook modules are NOT
// unit-tested here; their gate is typecheck + build.
export function fakePtr(bytes: number[]) {
  return {
    isNull: () => false,
    readByteArray: (n: number) => new Uint8Array(bytes.slice(0, n)).buffer,
    toString: () => "0xfake",
  };
}
