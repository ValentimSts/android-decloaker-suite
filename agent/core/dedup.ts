const CAP = 5000;
let store: Record<string, true> = {};
let size = 0;

export function hasSeen(sig: string): boolean {
  return store[sig] === true;
}

export function markSeen(sig: string): void {
  if (size >= CAP) {
    store = {};
    size = 0;
  }
  store[sig] = true;
  size++;
}

export function resetSeen(): void {
  store = {};
  size = 0;
}
