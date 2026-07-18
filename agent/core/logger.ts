import { config } from "../config";
import { hasSeen, markSeen } from "./dedup";
import type { LogLevel } from "../types";

export const C = {
  RESET: "\x1b[39;49;00m",
  RED: "\x1b[31;01m",
  GREEN: "\x1b[32;01m",
  YELLOW: "\x1b[33;01m",
  BLUE: "\x1b[34;01m",
  PURPLE: "\x1b[35;01m",
  CYAN: "\x1b[36;01m",
};

const MARK: Record<LogLevel, string> = {
  detect: "[!]",
  bypass: "[BYPASS]",
  dump: "[DUMP]",
  setup: "[+]",
  warn: "[-]",
  info: "[*]",
};

const COLOR: Record<LogLevel, string> = {
  detect: C.RED,
  bypass: C.RED,
  dump: C.PURPLE,
  setup: C.GREEN,
  warn: C.YELLOW,
  info: C.CYAN,
};

type Field = [label: string, value: string];

export function logLine(level: LogLevel, tag: string, message: string): void {
  if (level === "setup" && config.quietSetup) return;
  console.log(`\n${COLOR[level]}${MARK[level]} [${tag}] ${message}${C.RESET}`);
}

function emit(level: LogLevel, tag: string, headline: string, fields?: Field[], trace?: string) {
  if (level === "setup" && config.quietSetup) return;
  const head = `\n${COLOR[level]}${MARK[level]} [${tag}] ${headline}${C.RESET}`;
  console.log(head);
  if (fields) {
    for (const [label, value] of fields) {
      console.log(`${C.YELLOW}    -> ${label}: ${value}${C.RESET}`);
    }
  }
  if (trace) {
    console.log(`${C.BLUE}    -> Source Backtrace:\n    ${trace}${C.RESET}`);
  }
}

export const log = {
  detect: (tag: string, headline: string, fields?: Field[], trace?: string) =>
    emit("detect", tag, headline, fields, trace),
  bypass: (tag: string, headline: string, fields?: Field[]) =>
    emit("bypass", tag, headline, fields),
  dump: (tag: string, headline: string, fields?: Field[]) =>
    emit("dump", tag, headline, fields),
  setup: (tag: string, headline: string) => emit("setup", tag, headline),
  warn: (tag: string, headline: string) => emit("warn", tag, headline),
  info: (tag: string, headline: string) => emit("info", tag, headline),
  once(sig: string, fn: () => void) {
    if (hasSeen(sig)) return;
    markSeen(sig);
    fn();
  },
};
