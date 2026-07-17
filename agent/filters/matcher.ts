// Ported from legacy decloaker.js checkAndLog (lines 231-285).
//
// Key improvement over the legacy implementation: checkAndLog ran TWO passes over
// `value` - a TARGET_REGEX.test() to decide whether to proceed, then a full
// indexOf loop over ~90 TARGET_LOWER tokens to find which one matched and where.
// Here a single TARGET_REGEX.exec() (lexicon's regex has one capture group around
// the alternation) yields both the token (m[1]) and its index (m.index) in one pass.

import { TARGET_REGEX, BENIGN_FILTERS } from "./lexicon";
import { config } from "../config";
import { log, C } from "../core/logger";
import { hasSeen, markSeen } from "../core/dedup";
import { formatBacktrace } from "../core/backtrace";
import type { TraceThunk } from "../types";

export function scan(source: string, value: string, traceCb?: TraceThunk): string | false {
  if (!value) return false;
  TARGET_REGEX.lastIndex = 0;
  const m = TARGET_REGEX.exec(value);
  if (!m) return false;

  const backtrace = traceCb ? traceCb() : "";

  if (config.targetModules.length === 0 && backtrace) {
    const btLower = backtrace.toLowerCase();
    for (const b of BENIGN_FILTERS) {
      if (btLower.indexOf(b.toLowerCase()) !== -1) return false;
    }
  }

  const token = m[1];
  const idx = m.index;
  const start = Math.max(0, idx - 100);
  const end = Math.min(value.length, idx + token.length + 100);
  const before = value.substring(start, idx).replace(/\n/g, " ");
  const after = value.substring(idx + token.length, end).replace(/\n/g, " ");
  const highlighted =
    (start > 0 ? "... " : "") +
    before + C.GREEN + token + C.YELLOW + after +
    (end < value.length ? " ..." : "");

  const formattedBt = formatBacktrace(backtrace);
  const cleanSig = value.substring(0, 150).replace(/\n/g, " ");
  const signature = token + "|" + cleanSig + "|" + formattedBt;

  if (!hasSeen(signature)) {
    markSeen(signature);
    log.detect(source, "Detected target string match: " + token,
      [["Value", highlighted]], backtrace ? formattedBt : undefined);
  }
  return token;
}
