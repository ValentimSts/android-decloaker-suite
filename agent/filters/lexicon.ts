// Ported from legacy decloaker.js lines 81-182 (BENIGN_FILTERS, TARGET_STRINGS,
// TARGET_LOWER/TARGET_REGEX derivation, SPOOF_STRINGS, pathIsSpoofable).
//
// Retune (approved): dropped "mcc"/"mnc" (they match as substrings of many
// benign identifiers); narrowed "timezone" -> "persist.sys.timezone". Every
// other token, including broad ones like "organic", ".bundle", "adb_enabled",
// and "type_vpn", is deliberately retained - they are heavily used signals in
// campaign/conversion-data cloaking and evasion detection.

// ==========================================
// THE BENIGN FRAMEWORK FILTER
// ==========================================
export const BENIGN_FILTERS = [
  // --- Ad Networks & Analytics ---
  "com.google.android.gms", "com.applovin", "com.facebook.ads", "com.unity3d.ads",
  "com.vungle", "com.ironsource", "com.appsflyer", "com.adjust.sdk",

  // --- Common Framework Native Libs ---
  "libflutter.so", "libapp.so", "libreactnativejni.so", "libhermes.so", "libjsc.so",
  "libunity.so", "libil2cpp.so", "libmain.so", "libmonosgen-2.0.so", "libUE4.so",
  "libv8android.so", "libsigner.so",

  "libmonochrome_64.so",
];

// ==========================================
// THE EVASION LEXICON (TARGET STRINGS)
// ==========================================
export const TARGET_STRINGS = [
  // --- Frida & Hooking Artifacts ---
  "frida", "frida-server", "frida-agent", "libgadget.so", "pool-frida", "gdbus",
  "gum-js-loop", "gmain", "linjector", "hook_frida", "libjsig.so", "27042", "27043",
  "xposed", "substrate", "edxposed", "lsposed",

  // --- Root, Magisk & Privilege Escalation ---
  "magisk", "magisk.db", "daemonsu", "magisk_file", "/data/adb/magisk", "riru", "zygisk",
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "Superuser.apk",
  "test-keys", "ro.debuggable",

  // --- Emulators & Virtual Machines ---
  "qemu", "ro.kernel.qemu", "goldfish", "vbox86", "genymotion", "android_emulator",
  "bluestacks", "nox", "microvirt", "memu", "/dev/socket/qemud", "/dev/qemu_pipe",
  "ro.hardware.egl", "ro.kernel.android.qemud",

  // --- Packers, Protectors & Anti-Cheat ---
  "libjiagu.so", "libshell.so", "libDexHelper.so",

  // --- OS File System & State Evasion ---
  "/proc/self/maps", "/proc/self/mounts", "/proc/self/status", "/proc/tty/drivers",
  "ro.build.tags", "ro.build.fingerprint", "ro.product.model", "ro.build.id",
  "development_settings_enabled", "adb_enabled", "usb_mass_storage_enabled",
  "battery_property_capacity", "action_battery_changed", "sensormanager",

  // --- Dynamic Class Loading (DexGuard/Packers) ---
  "dexclassloader", "pathclassloader", "inmemorydexclassloader", "dalvik.system",
  ".dex", "extractDexPayloadConfig", "loadClass",

  // --- Game Engine & Asset Bundles ---
  "libcocos2djs.so", "project.manifest", "version.manifest", ".bundle", "assetbundle",

  // --- Telecom & Geo-Location Spoofing ---
  // Retune: "mcc"/"mnc" dropped (substring collisions with benign identifiers);
  // "timezone" narrowed to "persist.sys.timezone" (bare token was too broad).
  "getsimoperator", "getnetworkoperator", "getsimcountryiso",
  "ro.product.locale", "persist.sys.locale", "persist.sys.timezone",

  // --- Networking, VPN & External APIs ---
  "tun0", "ppp0", "type_vpn", "connectivity_action", "http.proxyhost", "java.net.useSystemProxies",
  "1e100.net", "ip-api.com", "ipinfo.io", "checkip.amazonaws.com", "api.ipify.org",
  "pastebin.com", "raw.githubusercontent.com", "duckdns.org",

  // --- Ads & Market Referrer Overrides ---
  "install_referrer", "com.android.vending.INSTALL_REFERRER",
  "utm_source", "utm_campaign", "organic", "adjust_referrer", "appsflyer", "af_status",
  "market://details?id=", "pm list packages", "com.android.vending",

  // --- Timing Checks (Anti-Debug) ---
  "system.currenttimemillis", "systemclock.elapsedrealtime", "alarmmanager",
];

// Precomputed lowercase copy of the lexicon (avoids re-lowercasing constants on every hot-path check).
export const TARGET_LOWER = TARGET_STRINGS.map((s) => s.toLowerCase());

// Maps a lowercased token back to its canonical TARGET_STRINGS spelling, so the
// matcher can report a stable, canonical token even though matching is case-insensitive.
export const CANON_BY_LOWER: Record<string, string> = (() => {
  const m: Record<string, string> = {};
  for (let i = 0; i < TARGET_STRINGS.length; i++) {
    const k = TARGET_LOWER[i];
    if (m[k] === undefined) m[k] = TARGET_STRINGS[i];
  }
  return m;
})();

// Escape ALL regex metacharacters (not just "."), so tokens like "market://details?id=" are
// matched literally and cannot silently drift or throw when the RegExp is built. Single capture
// group so the matcher can pull the matched token and its index out of one exec() call.
export const TARGET_REGEX = new RegExp(
  "(" + TARGET_STRINGS.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")",
  "i"
);

// DETECTION vs BYPASS split. The full TARGET_STRINGS lexicon above drives DETECTION/logging.
// Active bypass (spoofing I/O to failure) is far riskier - a false positive on a broad token
// like "timezone" or ".bundle" would break legitimate app I/O - so it is gated on this much
// narrower, high-confidence allowlist of genuine cloaking artifacts only.
export const SPOOF_STRINGS = [
  // Frida / hooking artifacts
  "frida", "frida-server", "frida-agent", "libgadget.so", "pool-frida",
  "gum-js-loop", "gmain", "linjector", "27042", "27043",
  "xposed", "edxposed", "lsposed", "substrate",
  // Root / Magisk
  "magisk", "magisk.db", "daemonsu", "magisk_file", "/data/adb/magisk", "riru", "zygisk",
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "superuser.apk",
  // Emulator device nodes / properties
  "ro.kernel.qemu", "goldfish", "/dev/socket/qemud", "/dev/qemu_pipe", "ro.kernel.android.qemud",
  // Packers
  "libjiagu.so", "libshell.so", "libdexhelper.so",
];

// True if the value contains ANY narrow-allowlist artifact. Scans the full path/property rather
// than checkAndLog's first-match token, so a broad token like "qemu" cannot shadow a spoofable
// artifact such as "/dev/qemu_pipe" and silently prevent its bypass. SPOOF_STRINGS are lowercase.
export function pathIsSpoofable(value: unknown): boolean {
  if (!value) return false;
  const l = String(value).toLowerCase();
  for (let i = 0; i < SPOOF_STRINGS.length; i++) {
    if (l.indexOf(SPOOF_STRINGS[i]) !== -1) return true;
  }
  return false;
}
