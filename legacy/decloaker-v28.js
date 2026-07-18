// ==========================================
// Sigma Decloaker V28
// ==========================================

var C = {
    RESET: "\x1b[39;49;00m", RED: "\x1b[31;01m", GREEN: "\x1b[32;01m",
    YELLOW: "\x1b[33;01m", BLUE: "\x1b[34;01m", PURPLE: "\x1b[35;01m", CYAN: "\x1b[36;01m"
};

// Global cache to prevent printing identical duplicate hooks (e.g., access calling faccessat).
// Bounded to avoid unbounded memory growth over long sessions: reset once it exceeds the cap.
var ALERT_HISTORY = {};
var ALERT_HISTORY_SIZE = 0;
var ALERT_HISTORY_CAP = 5000;

function markSeen(signature) {
    if (ALERT_HISTORY_SIZE >= ALERT_HISTORY_CAP) {
        ALERT_HISTORY = {};
        ALERT_HISTORY_SIZE = 0;
    }
    ALERT_HISTORY[signature] = true;
    ALERT_HISTORY_SIZE++;
}

// ==========================================
// CONFIGURATION & FLAGS
// ==========================================

var FULL_BACKTRACE = false; 

// [ACTIVE BYPASS]: If true, intercepts file reads to targets (e.g., su, frida) and forces them to return "File Not Found".
// Also actively bypasses ptrace(PTRACE_TRACEME).
// Default OFF: observe first. Enable at runtime via the setbypass RPC when you deliberately
// want to defeat cloaking. When enabled, active bypass MUTATES the analyzed sample's behavior.
var ACTIVE_BYPASS = true; 

// Add specific native libraries (.so) to ONLY analyze calls from them. Leave empty [] for global.
var TARGET_MODULES = ["liblqcmyholfftjmi.so"];

// [PAYLOAD DUMPING]: when true, decrypted/unpacked buffers (dex/elf/config/payloads captured by the
// crypto, ART-dex, JNI byte-array, and memory-unpacking hooks) are written to DUMP_DIR on the device.
// Off by default - dumping is high volume and writes to disk. Toggle at runtime via the setdump RPC.
var DUMP_PAYLOADS = false;
var DUMP_DIR = "/data/local/tmp";

// If true, hex previews of large buffers are truncated to 128 bytes in the console log.
var TRUNCATE_HEX = false; 

// [MEMORY-PROTECTION HOOKS]: Interceptor hooks on mprotect/mmap/munmap/remap_file_pages.
// DISABLED by default: ART's JIT and the heap profiler (perfetto_hprof) manage executable memory
// through these constantly, and intercepting them under Frida on Android is known to corrupt that
// (a page that should become executable does not -> SIGSEGV "trying to execute non-executable
// memory"). Enable (set to true and re-inject) only if the target is stable with it on.
// memfd_create is unaffected and always hooked.
var HOOK_MEMORY_PROTECTION = false;

// [VERBOSITY] When true, the green "[+] ..." hook-setup confirmation lines are suppressed so the
// console shows only detections ([!]), warnings/failures ([-]) and the banner ([*]) - useful for
// cutting the startup spam once you trust the hooks installed. Toggle at runtime via the setquiet
// RPC. Detections and alerts are NEVER suppressed. Set to true to start quiet.
var QUIET_SETUP = true;

// Install a console.log filter for the QUIET_SETUP flag. Only the green "[+]" setup lines carry
// that marker; detections use "[!]", warnings "[-]", the banner "[*]", so none of those are hidden.
(function () {
    try {
        var _rawLog = console.log.bind(console);
        console.log = function () {
            if (QUIET_SETUP && arguments.length > 0 && typeof arguments[0] === "string" &&
                arguments[0].indexOf("[+]") !== -1) {
                return;
            }
            return _rawLog.apply(null, arguments);
        };
    } catch (e) { /* console.log not reassignable on this runtime; QUIET_SETUP is then a no-op */ }
})();

// ==========================================
// THE BENIGN FRAMEWORK FILTER
// ==========================================
var BENIGN_FILTERS = [
    // --- Ad Networks & Analytics ---
    "com.google.android.gms", "com.applovin", "com.facebook.ads", "com.unity3d.ads", 
    "com.vungle", "com.ironsource", "com.appsflyer", "com.adjust.sdk",
    
    // --- Common Framework Native Libs ---
    "libflutter.so", "libapp.so", "libreactnativejni.so", "libhermes.so", "libjsc.so", 
    "libunity.so", "libil2cpp.so", "libmain.so", "libmonosgen-2.0.so", "libUE4.so", 
    "libv8android.so", "libsigner.so",

    "libmonochrome_64.so"
]; 

// ==========================================
// THE EVASION LEXICON (TARGET STRINGS)
// ==========================================
var TARGET_STRINGS = [
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
    "getsimoperator", "getnetworkoperator", "getsimcountryiso",
    "ro.product.locale", "persist.sys.locale", "mcc", "mnc", "timezone",

    // --- Networking, VPN & External APIs ---
    "tun0", "ppp0", "type_vpn", "connectivity_action", "http.proxyhost", "java.net.useSystemProxies",
    "1e100.net", "ip-api.com", "ipinfo.io", "checkip.amazonaws.com", "api.ipify.org",
    "pastebin.com", "raw.githubusercontent.com", "duckdns.org",

    // --- Ads & Market Referrer Overrides ---
    "install_referrer", "com.android.vending.INSTALL_REFERRER", 
    "utm_source", "utm_campaign", "organic", "adjust_referrer", "appsflyer", "af_status",
    "market://details?id=", "pm list packages", "com.android.vending",

    // --- Timing Checks (Anti-Debug) ---
    "system.currenttimemillis", "systemclock.elapsedrealtime", "alarmmanager"
];

// Precomputed lowercase copy of the lexicon (avoids re-lowercasing constants on every hot-path check).
var TARGET_LOWER = TARGET_STRINGS.map(function(s) { return s.toLowerCase(); });

// Escape ALL regex metacharacters (not just "."), so tokens like "market://details?id=" are
// matched literally and cannot silently drift or throw when the RegExp is built.
var regexStr = TARGET_STRINGS.map(function(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }).join("|");
var TARGET_REGEX = new RegExp(regexStr, "i");

// DETECTION vs BYPASS split. The full TARGET_STRINGS lexicon above drives DETECTION/logging.
// Active bypass (spoofing I/O to failure) is far riskier - a false positive on a broad token
// like "timezone" or ".bundle" would break legitimate app I/O - so it is gated on this much
// narrower, high-confidence allowlist of genuine cloaking artifacts only.
var SPOOF_STRINGS = [
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
    "libjiagu.so", "libshell.so", "libdexhelper.so"
];
// True if the value contains ANY narrow-allowlist artifact. Scans the full path/property rather
// than checkAndLog's first-match token, so a broad token like "qemu" cannot shadow a spoofable
// artifact such as "/dev/qemu_pipe" and silently prevent its bypass. SPOOF_STRINGS are lowercase.
function pathIsSpoofable(value) {
    if (!value) return false;
    var l = String(value).toLowerCase();
    for (var i = 0; i < SPOOF_STRINGS.length; i++) {
        if (l.indexOf(SPOOF_STRINGS[i]) !== -1) return true;
    }
    return false;
}

// ==========================================
// LOGIC ENFORCEMENT & UTILITIES
// ==========================================

function getExportSafe(moduleName, funcName) {
    try {
        var mod = Process.getModuleByName(moduleName);
        return mod.getExportByName(funcName);
    } catch (e) { return null; }
}

function readStrSafe(ptr, limit) {
    try {
        if (ptr != null && !ptr.isNull()) {
            if (limit) return ptr.readUtf8String(limit) || "";
            return ptr.readUtf8String() || "";
        }
    } catch (e) {}
    return "";
}

function getNativeBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.FUZZY)
                     .map(DebugSymbol.fromAddress)
                     .join("\n    ");
    } catch (e) { return ""; }
}

function formatBacktrace(btStr) {
    if (!btStr) return "[Native Backtrace unavailable]";
    if (FULL_BACKTRACE) return btStr;
    var lines = btStr.split("\n    ");
    if (lines.length > 5) return lines.slice(0, 5).join("\n    ") + "\n    ... [TRUNCATED - Set FULL_BACKTRACE=true to expand]";
    return btStr;
}

function isTargetCaller(returnAddress) {
    if (TARGET_MODULES.length === 0) return true; 
    var mod = Process.findModuleByAddress(returnAddress);
    if (!mod) return false;
    for (var i = 0; i < TARGET_MODULES.length; i++) {
        if (mod.name === TARGET_MODULES[i]) return true;
    }
    return false;
}

function checkAndLog(source, value, traceCallback) {
    if (!value || !TARGET_REGEX.test(value)) return false;
    
    var backtrace = traceCallback ? traceCallback() : "";

    if (TARGET_MODULES.length === 0 && backtrace) {
        var btLower = backtrace.toLowerCase();
        for (var j = 0; j < BENIGN_FILTERS.length; j++) {
            if (btLower.indexOf(BENIGN_FILTERS[j].toLowerCase()) !== -1) return false; 
        }
    }

    var lowerStr = value.toLowerCase();
    for (var i = 0; i < TARGET_STRINGS.length; i++) {
        var matchIdx = lowerStr.indexOf(TARGET_LOWER[i]);
        if (matchIdx !== -1) {
            
            // Get the exact match (preserving its original case)
            var matchLen = TARGET_STRINGS[i].length;
            var exactMatch = value.substring(matchIdx, matchIdx + matchLen);
            
            // Create a 200-character context window centered around the match
            var startIdx = Math.max(0, matchIdx - 100);
            var endIdx = Math.min(value.length, matchIdx + matchLen + 100);
            
            // Clean up newlines so the console log doesn't break vertically
            var beforeMatch = value.substring(startIdx, matchIdx).replace(/\n/g, " ");
            var afterMatch = value.substring(matchIdx + matchLen, endIdx).replace(/\n/g, " ");
            
            // Build the string: Yellow context -> Green Match -> Yellow context
            var highlightedVal = (startIdx > 0 ? "... " : "") + 
                                 beforeMatch + 
                                 C.GREEN + exactMatch + C.YELLOW + 
                                 afterMatch + 
                                 (endIdx < value.length ? " ..." : "");
            
            var formattedBt = formatBacktrace(backtrace);
            
            // Use a clean, truncated version of the raw value for the dedup signature
            var cleanSigVal = value.substring(0, 150).replace(/\n/g, " ");
            var signature = TARGET_STRINGS[i] + "|" + cleanSigVal + "|" + formattedBt;
            
            if (!ALERT_HISTORY[signature]) {
                markSeen(signature);
                
                console.log("\n" + C.RED + "[!] [" + source + "] Detected target string match: " + TARGET_STRINGS[i] + C.RESET);
                console.log(C.YELLOW + "    -> Value: " + highlightedVal + C.RESET);
                if (backtrace) console.log(C.BLUE + "    -> Source Backtrace:\n    " + formattedBt + C.RESET);
            }
            
            return TARGET_STRINGS[i];
        }
    }
    return false;
}

// ==========================================
// PAYLOAD / BUFFER HELPERS (shared by crypto, ART-dex, JNI array, and memory-unpacking hooks)
// ==========================================

// Hex string of up to maxLen bytes at p (default 64). Null/fault safe.
function hexPreview(p, maxLen) {
    try {
        if (!p || p.isNull()) return "";
        var n = maxLen || 64;
        var bytes = new Uint8Array(p.readByteArray(n));
        var len = bytes.length;
        var hex = "";
        
        if (!TRUNCATE_HEX || len <= 24) {
            for (var i = 0; i < len; i++) {
                var h = (bytes[i] & 0xff).toString(16);
                hex += (h.length === 1 ? "0" + h : h);
            }
        } else {
            for (var i = 0; i < 8; i++) {
                var h = (bytes[i] & 0xff).toString(16);
                hex += (h.length === 1 ? "0" + h : h);
            }
            hex += "...";
            for (var i = len - 8; i < len; i++) {
                var h = (bytes[i] & 0xff).toString(16);
                hex += (h.length === 1 ? "0" + h : h);
            }
            hex += " (" + len + " bytes)";
        }
        return hex;
    } catch (e) { return ""; }
}

// Identify a decrypted/unpacked payload by its leading magic bytes.
function payloadMagic(p) {
    try {
        if (!p || p.isNull()) return null;
        var b = new Uint8Array(p.readByteArray(4));
        if (b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a) return "dex";   // "dex\n"
        if (b[0] === 0x63 && b[1] === 0x64 && b[2] === 0x65 && b[3] === 0x78) return "cdex";   // "cdex"
        if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "elf";    // 0x7f ELF
        if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return "zip";    // PK..
        return null;
    } catch (e) { return null; }
}

// Log (always) and, when DUMP_PAYLOADS is on, write a captured buffer to DUMP_DIR. Deduped.
function dumpBuffer(tag, p, len) {
    try {
        if (!p || p.isNull() || !len || len <= 0) return;
        var magic = payloadMagic(p);
        var sig = "dump|" + tag + "|" + p + "|" + len;
        if (ALERT_HISTORY[sig]) return;
        markSeen(sig);
        console.log(C.PURPLE + "[!] [DUMP] " + tag + " size=" + len + (magic ? " magic=" + magic : "") +
                    " head=" + hexPreview(p, 32) + C.RESET);
        if (DUMP_PAYLOADS) {
            var cap = len < (16 * 1024 * 1024) ? len : (16 * 1024 * 1024); // safety cap 16 MB
            var fname = DUMP_DIR + "/amas_" + String(tag).replace(/[^a-zA-Z0-9_.-]/g, "_") + "_" +
                        String(p).replace(/^0x/, "") + (magic ? "." + magic : ".bin");
            var f = new File(fname, "wb");
            f.write(p.readByteArray(cap));
            f.close();
            console.log(C.GREEN + "    -> dumped to " + fname + C.RESET);
        }
    } catch (e) {
        console.log(C.RED + "    -> [!] dumpBuffer error: " + e.message + C.RESET);
    }
}

// ==========================================
// RPC EXPORTS (Live Toggles)
// ==========================================
rpc.exports = {
    addtarget: function(elfName) {
        if (TARGET_MODULES.indexOf(elfName) === -1) {
            TARGET_MODULES.push(elfName);
            if (Process.findModuleByName(elfName) === null) {
                console.log(C.YELLOW + "[!] Warning: '" + elfName + "' is not currently loaded in memory." + C.RESET);
            } else {
                console.log(C.GREEN + "[+] Now exclusively analyzing module: " + elfName + C.RESET);
            }
        }
    },
    cleartargets: function() {
        TARGET_MODULES = [];
        console.log(C.GREEN + "[+] Cleared exclusive targets. Reverting to global analysis." + C.RESET);
    },
    setfulltrace: function(enabled) { FULL_BACKTRACE = !!enabled; },
    setbypass: function(enabled) {
        ACTIVE_BYPASS = !!enabled;
        console.log(C.RED + "[!] Active Bypass Mode is now: " + (ACTIVE_BYPASS ? "ENABLED" : "DISABLED") + C.RESET);
    },
    setdump: function(enabled) {
        DUMP_PAYLOADS = !!enabled;
        console.log(C.PURPLE + "[!] Payload Dumping is now: " + (DUMP_PAYLOADS ? "ENABLED -> " + DUMP_DIR : "DISABLED") + C.RESET);
    },
    setquiet: function(enabled) {
        QUIET_SETUP = !!enabled;
        // Uses "[*]" (not "[+]") so this confirmation is shown even while quiet.
        console.log(C.CYAN + "[*] Setup-log verbosity: " + (QUIET_SETUP ? "QUIET (hiding [+] setup lines)" : "verbose") + C.RESET);
    },
    settruncatehex: function(enabled) {
        TRUNCATE_HEX = !!enabled;
        console.log(C.GREEN + "[*] TRUNCATE_HEX set to: " + TRUNCATE_HEX + C.RESET);
    }
};

// ==========================================
// ANTI-EMULATION & NATIVE HOOKS
// ==========================================

function hookSystemProperties() {
    var sysPropGet = getExportSafe("libc.so", "__system_property_get");
    if (sysPropGet) {
        Interceptor.attach(sysPropGet, {
            onEnter: function(args) {
                this.propName = readStrSafe(args[0]);
                this.valBuf = args[1]; 
            },
            onLeave: function(retval) {
                if (!this.propName || (this.propName.indexOf("ro.") !== 0 && this.propName.indexOf("gsm.") !== 0)) return;

                var propValue = "";
                if (this.valBuf && !this.valBuf.isNull()) {
                    propValue = readStrSafe(this.valBuf);
                }
                
                // Check if we have seen this exact property query before
                var sig = "sysprop_get|" + this.propName;
                var seen = !!ALERT_HISTORY[sig];

                // --- UPDATED ACTIVE BYPASS ---
                // We MUST perform the writeUtf8String every time so the malware 
                // gets the fake value, but we only console.log if (!seen).
                if (ACTIVE_BYPASS && this.valBuf && !this.valBuf.isNull()) {
                    if (this.propName === "ro.arch") {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing ro.arch to arm64-v8a" + C.RESET);
                        this.valBuf.writeUtf8String("arm64-v8a");
                        propValue = "arm64-v8a";
                    } else if (this.propName === "ro.build.version.codename") {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing ro.build.version.codename to REL" + C.RESET);
                        this.valBuf.writeUtf8String("REL");
                        propValue = "REL";
                    } else if (this.propName === "ro.input.resampling") {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing ro.input.resampling to 1" + C.RESET);
                        this.valBuf.writeUtf8String("1");
                        propValue = "1";
                    } else if (this.propName === "ro.build.version.release") {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing ro.build.version.release to 14" + C.RESET);
                        this.valBuf.writeUtf8String("14");
                        propValue = "14";
                    } else if (this.propName === "ro.build.version.sdk") {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing ro.build.version.sdk to 34" + C.RESET);
                        this.valBuf.writeUtf8String("34");
                        propValue = "34";
                    }
                }
                // ------------------------------

                // Stop here if we've already logged this property
                if (seen) return;
                markSeen(sig);

                console.log("\n" + C.PURPLE + "[!] [SYS-PROP] __system_property_get" + C.RESET);
                console.log(C.YELLOW + "    -> Queried: " + this.propName + " = " + (propValue ? propValue : "[empty]") + C.RESET);
            }
        });
        console.log(C.GREEN + "[+] Hooked Native System Properties (__system_property_get)" + C.RESET);
    }
}

function hookNativeFileIO() {
    // FIXED: Use getExportSafe here as well
    var openatPtr = getExportSafe("libc.so", "openat");
    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            onEnter: function(args) {
                var path = args[1].readUtf8String();
                if (path && (path.indexOf("/proc/") !== -1 || path.indexOf("/sys/") !== -1 || path.indexOf("qemu") !== -1)) {
                    console.log(C.CYAN + "[!] [FILE I/O] openat detected anti-analysis read" + C.RESET);
                    console.log(C.YELLOW + "    -> Target: " + path + C.RESET);
                }
            }
        });
    }
    console.log(C.GREEN + "[+] Hooked Native File I/O (openat)" + C.RESET);
}

function scanModuleMemory(libName) {
    // Convert short name (e.g., "gdresourcekit") to map name ("libgdresourcekit.so")
    var actualName = libName;
    if (!actualName.startsWith("lib")) actualName = "lib" + actualName;
    if (!actualName.endsWith(".so")) actualName = actualName + ".so";

    var m = Process.findModuleByName(actualName);
    if (!m) return;

    console.log(C.BLUE + "\n[*] Scanning memory of " + actualName + " for suspicious strings..." + C.RESET);
    
    var patterns = [
        { name: "QEMU Pipe", hex: "71 65 6d 75 5f 70 69 70 65" }, // qemu_pipe
        { name: "Rust Reqwest", hex: "72 65 71 77 65 73 74" }, // reqwest
        { name: "Substratum", hex: "73 75 62 73 74 72 61 74 75 6d" }, // substratum
        { name: "ro.arch string", hex: "72 6f 2e 61 72 63 68" } // ro.arch
    ];

    patterns.forEach(function(pattern) {
        Memory.scan(m.base, m.size, pattern.hex, {
            onMatch: function(address, size) {
                console.log(C.RED + "    -> [!] Found embedded string: [" + pattern.name + "] at " + address + C.RESET);
            },
            onError: function(reason) {},
            onComplete: function() {}
        });
    });
}

// ==========================================
// JAVA CLASS & NATIVE LIBRARY LOADING HOOKS
// ==========================================

function hookJavaNativeLoaders() {
    if (!Java.available) return;

    Java.perform(function() {
        var System = Java.use("java.lang.System");
        var Runtime = Java.use("java.lang.Runtime");
        var Log = Java.use("android.util.Log");
        var Exception = Java.use("java.lang.Exception");
        var Thread = Java.use("java.lang.Thread");

        function logNativeLoad(methodName, libName) {
            console.log("\n" + C.PURPLE + "[!] [NATIVE LOAD] Dynamic Library Load Detected: " + methodName + C.RESET);
            console.log(C.YELLOW + "    -> Target: " + libName + C.RESET);
            
            var instance = Exception.$new("NativeLoadTrace");
            var stack = Log.getStackTraceString(instance).split('\n');
            var cleanStack = stack.slice(1, 8).join('\n    '); 
            console.log(C.BLUE + "    -> Java Backtrace:\n    " + cleanStack + C.RESET);
        }

        System.load.overload('java.lang.String').implementation = function(filename) {
            logNativeLoad("System.load", filename);
            return this.load(filename);
        };

        System.loadLibrary.overload('java.lang.String').implementation = function(libname) {
            logNativeLoad("System.loadLibrary", libname);

            // FIX: the script kept crashing with monochrome and webview related errors.
            if (libname.indexOf("monochrome") !== -1 || libname.indexOf("webview") !== -1) {
                return this.loadLibrary(libname); // Let system libraries fail naturally without sleeping
            }

            try {
                var result = this.loadLibrary(libname);
                
                // INJECT HERE: Scan the library immediately after it successfully loads
                if (!isSystemLib) scanModuleMemory(libname);
                
                return result;
            } catch (e) {
                console.log(C.RED + "    -> [!] UnsatisfiedLinkError. Suspected extraction race condition." + C.RESET);
                console.log(C.YELLOW + "    -> Sleeping for 3 seconds to allow dropping to finish..." + C.RESET);
                Thread.sleep(3000); // 3 second stall

                var result = this.loadLibrary(libname);
                console.log(C.GREEN + "    -> [+] Retry successful!" + C.RESET);

                // INJECT HERE: Scan the library if the retry was successful
                scanModuleMemory(libname);

                return result;
            }
        };

        Runtime.load.overload('java.lang.String').implementation = function(filename) {
            logNativeLoad("Runtime.load", filename);
            return this.load(filename);
        };

        try {
            Runtime.loadLibrary.overload('java.lang.String').implementation = function(libname) {
                logNativeLoad("Runtime.loadLibrary", libname);
                try {
                    return this.loadLibrary(libname);
                } catch (e) {
                    console.log(C.RED + "    -> [!] UnsatisfiedLinkError. Suspected extraction race condition." + C.RESET);
                    console.log(C.YELLOW + "    -> Sleeping for 3 seconds to allow dropping to finish..." + C.RESET);
                    Thread.sleep(3000);
                    var result = this.loadLibrary(libname);
                    console.log(C.GREEN + "    -> [+] Retry successful!" + C.RESET);
                    return result;
                }
            };
        } catch(e) { 
            console.log(C.YELLOW + "[-] Runtime.loadLibrary hook unavailable: " + e.message + C.RESET); 
        }

        console.log(C.GREEN + "[+] Hooked Java Native Loaders (System.load, System.loadLibrary) with Race Condition Fix" + C.RESET);
    });
}

function hookJavaDCL() {
    if (!Java.available) {
        console.log(C.YELLOW + "[!] Java is not available. Skipping DCL hooks." + C.RESET);
        return;
    }

    Java.perform(function() {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        var Log = Java.use("android.util.Log");
        var Exception = Java.use("java.lang.Exception");

        function logDCL(type, dexPath, optimizedDirectory, librarySearchPath) {
            console.log("\n" + C.PURPLE + "[!] [DCL] Suspicious Dynamic Class Loading Detected: " + type + C.RESET);
            if (dexPath) console.log(C.YELLOW + "    -> Target: " + dexPath + C.RESET);
            if (optimizedDirectory) console.log(C.YELLOW + "    -> Opt Dir: " + optimizedDirectory + C.RESET);
            if (librarySearchPath) console.log(C.YELLOW + "    -> Lib Path: " + librarySearchPath + C.RESET);
            
            var instance = Exception.$new("DCLStackTrace");
            var stack = Log.getStackTraceString(instance).split('\n');
            var cleanStack = stack.slice(1, 8).join('\n    '); 
            console.log(C.BLUE + "    -> Java Backtrace:\n    " + cleanStack + C.RESET);
        }

        DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            logDCL("DexClassLoader", dexPath, optimizedDirectory, librarySearchPath);
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };

        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, parent) {
            logDCL("PathClassLoader", dexPath, null, null);
            return this.$init(dexPath, parent);
        };
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, librarySearchPath, parent) {
            logDCL("PathClassLoader", dexPath, null, librarySearchPath);
            return this.$init(dexPath, librarySearchPath, parent);
        };

        try {
            InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(dexBuffer, parent) {
                logDCL("InMemoryDexClassLoader", "Memory Buffer (Capacity: " + dexBuffer.capacity() + ")", null, null);
                return this.$init(dexBuffer, parent);
            };
            InMemoryDexClassLoader.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader').implementation = function(dexBuffers, parent) {
                logDCL("InMemoryDexClassLoader", "Memory Buffer Array (Length: " + dexBuffers.length + ")", null, null);
                return this.$init(dexBuffers, parent);
            };
        } catch(e) { console.log(C.YELLOW + "[-] InMemoryDexClassLoader hook unavailable: " + e.message + C.RESET); }
        
        console.log(C.GREEN + "[+] Hooked Java DCL APIs (DexClassLoader, PathClassLoader, InMemoryDexClassLoader)" + C.RESET);
    });
}

// ==========================================
// NETWORK & SSL/TLS INTERCEPTOR (JSON PAYLOADS)
// ==========================================

// Cap how many bytes we ever scan from a single network buffer. Bounds both the string-build
// cost and the downstream JSON matching (buffers can be up to ~1MB), neutralizing the DoS/ReDoS.
var NET_SCAN_CAP = 65536;

// Utility to safely extract printable strings from raw memory buffers
function readPrintableString(ptr, size) {
    if (ptr.isNull() || size <= 0) return null;
    try {
        var scan = size < NET_SCAN_CAP ? size : NET_SCAN_CAP;
        var buf = ptr.readByteArray(scan);
        var bytes = new Uint8Array(buf);
        var chars = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i];
            if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) {
                chars.push(b);
            }
        }
        // Build in bounded chunks; per-char string concatenation on large buffers is very slow.
        var str = "";
        for (var j = 0; j < chars.length; j += 8192) {
            str += String.fromCharCode.apply(null, chars.slice(j, j + 8192));
        }
        return str;
    } catch (e) { return null; }
}

// Heuristic to detect if a string contains a JSON payload
function detectJSON(str) {
    if (!str) return null;
    // Bound the input and use non-backtracking character classes ([^{}] instead of greedy .*)
    // so a quote-heavy non-JSON buffer cannot trigger catastrophic backtracking (ReDoS).
    if (str.length > NET_SCAN_CAP) str = str.substring(0, NET_SCAN_CAP);
    var match = str.match(/(\{[^{}]*"[\w]+"\s*:\s*[^{}]*\}|\[\s*\{[^{}]*\}\s*\])/s);
    if (match) {
        try {
            JSON.parse(match[0]);
            return match[0];
        } catch (e) {
            if (match[0].indexOf('":') !== -1) return match[0];
        }
    }
    return null;
}

function processNetworkBuffer(funcName, bufferPtr, size, context) {
    var rawStr = readPrintableString(bufferPtr, size);
    if (!rawStr) return;

    var jsonPayload = detectJSON(rawStr);
    
    if (jsonPayload) {
        var bt = getNativeBacktrace(context);
        var signature = funcName + "|" + jsonPayload.substring(0, 200);

        if (!ALERT_HISTORY[signature]) {
            markSeen(signature);
            console.log("\n" + C.CYAN + "[!] [NETWORK] Intercepted JSON Payload via: " + funcName + C.RESET);
            
            try {
                var parsed = JSON.parse(jsonPayload);
                console.log(C.YELLOW + JSON.stringify(parsed, null, 2) + C.RESET);
            } catch(e) {
                console.log(C.YELLOW + jsonPayload + C.RESET);
            }
            
            if (FULL_BACKTRACE) {
                console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(bt) + C.RESET);
            }
        }
    } else if (size > 0) {
        // This is likely a binary WebSocket frame or a non-JSON protocol
        console.log(C.PURPLE + "\n[!] [RAW-NET] " + funcName + " (" + size + " bytes)" + C.RESET);
        console.log(C.YELLOW + "    -> Hex: " + hexPreview(bufferPtr, 128) + C.RESET);
    } else {
        checkAndLog("NETWORK: " + funcName, rawStr, function() { return getNativeBacktrace(context); });
    }
}

function hookNetworkTraffic() {
    var networkFuncs = [
        // 1. Android/BoringSSL TLS
        { mod: "libssl.so", func: "SSL_write", bufIdx: 1, sizeIdx: 2, isEnter: true },
        { mod: "libssl.so", func: "SSL_read", bufIdx: 1, sizeIdx: 2, isEnter: false },
        { mod: "libjavacrypto.so", func: "SSL_write", bufIdx: 1, sizeIdx: 2, isEnter: true }, 
        { mod: "libjavacrypto.so", func: "SSL_read", bufIdx: 1, sizeIdx: 2, isEnter: false },
        
        // 2. Standard Libc Sockets
        { mod: "libc.so", func: "send", bufIdx: 1, sizeIdx: 2, isEnter: true },
        { mod: "libc.so", func: "sendto", bufIdx: 1, sizeIdx: 2, isEnter: true },
        { mod: "libc.so", func: "recv", bufIdx: 1, sizeIdx: 2, isEnter: false },
        { mod: "libc.so", func: "recvfrom", bufIdx: 1, sizeIdx: 2, isEnter: false },
    ];

    // NOTE: `let` (block scope) is required here. With `var`, the single function-scoped
    // binding is shared by every Interceptor callback, so all hooks would run with the LAST
    // cfg - silently breaking outbound (SSL_write/send) inspection and mislabeling every alert.
    for (let i = 0; i < networkFuncs.length; i++) {
        let cfg = networkFuncs[i];
        let ptrAddress = getExportSafe(cfg.mod, cfg.func);
        
        if (ptrAddress) {
            Interceptor.attach(ptrAddress, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    
                    this.bufPtr = args[cfg.bufIdx];
                    this.size = args[cfg.sizeIdx].toInt32();
                    this.ctx = this.context;

                    if (cfg.isEnter && this.size > 0 && this.size < 1048576) { 
                        processNetworkBuffer(cfg.func, this.bufPtr, this.size, this.ctx);
                    }
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    
                    var bytesRead = retval.toInt32();
                    if (!cfg.isEnter && bytesRead > 0 && bytesRead < 1048576) {
                        processNetworkBuffer(cfg.func, this.bufPtr, bytesRead, this.ctx);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Network IO: " + cfg.func + " (" + cfg.mod + ")" + C.RESET);
        }
    }
}

// ==========================================
// ADVANCED PROCESS, LINKING & ANTI-DEBUG HOOKS
// ==========================================

function hookDeepExecution() {
    var execvePtr = getExportSafe("libc.so", "execve");
    if (execvePtr) {
        Interceptor.attach(execvePtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) return;
                var cmd = readStrSafe(args[0]);
                var argv = args[1];
                var fullCmd = cmd;
                if (!argv.isNull()) {
                    fullCmd += " ";
                    for (var i = 1; i < 15; i++) { 
                        var argPtr = argv.add(i * Process.pointerSize).readPointer();
                        if (argPtr.isNull()) break;
                        fullCmd += readStrSafe(argPtr) + " ";
                    }
                }
                var ctx = this.context;
                checkAndLog("execve", fullCmd, function() { return getNativeBacktrace(ctx); });
            }
        });
        console.log(C.GREEN + "[+] Hooked Process: execve" + C.RESET);
    }

    var ptracePtr = getExportSafe("libc.so", "ptrace");
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                this.skip = false;
                this.req = args[0].toInt32();
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (this.skip) return;
                if (this.req === 0) { 
                    console.log("\n" + C.PURPLE + "[!] [ptrace] Anti-Debugging PTRACE_TRACEME detected!" + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(getNativeBacktrace(this.ctx)) + C.RESET);
                    
                    if (ACTIVE_BYPASS) {
                        console.log(C.RED + "    -> [BYPASS] Spoofing ptrace success (Returning 0)." + C.RESET);
                        retval.replace(ptr("0x0"));
                    }
                }
            }
        });
        console.log(C.GREEN + "[+] Hooked Anti-Debug: ptrace" + C.RESET);
    }

    function attachReadlink(funcName, argIdx) {
        var rlPtr = getExportSafe("libc.so", funcName);
        if (rlPtr) {
            Interceptor.attach(rlPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var path = readStrSafe(args[argIdx]);
                    var ctx = this.context;
                    checkAndLog(funcName, path, function() { return getNativeBacktrace(ctx); });
                }
            });
        }
    }
    attachReadlink("readlink", 0);
    attachReadlink("readlinkat", 1);
}

// ==========================================
// CORE I/O HOOKS (WITH ACTIVE BYPASS)
// ==========================================

// Lazily-resolved libc helpers used to keep active bypass semantically correct.
var _closeFn = null, _errnoLoc = null;

function libcClose(fd) {
    try {
        if (_closeFn === null) {
            var p = getExportSafe("libc.so", "close");
            _closeFn = p ? new NativeFunction(p, 'int', ['int']) : false;
        }
        if (_closeFn) _closeFn(fd);
    } catch (e) {}
}

function setErrnoENOENT() {
    try {
        if (_errnoLoc === null) {
            var p = getExportSafe("libc.so", "__errno_location");
            _errnoLoc = p ? new NativeFunction(p, 'pointer', []) : false;
        }
        if (_errnoLoc) _errnoLoc().writeInt(2); // ENOENT
    } catch (e) {}
}

function safeAttachIO(moduleName, funcName, argIndex) {
    var ptrAddress = getExportSafe(moduleName, funcName);
    if (!ptrAddress) return;
    try {
        Interceptor.attach(ptrAddress, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                this.skip = false;
                this.pathStr = readStrSafe(args[argIndex]);
                this.args = args; 
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (this.skip || !this.pathStr) return;
                var ctx = this.ctx;
                var match = checkAndLog(funcName, this.pathStr, function() { return getNativeBacktrace(ctx); });

                // Detection fires on the full lexicon, but only spoof when the path itself contains
                // a narrow-allowlist artifact - never spoof legitimate paths on a broad token match.
                if (match && ACTIVE_BYPASS && pathIsSpoofable(this.pathStr)) {
                    console.log(C.RED + "    -> [BYPASS] Spoofing Bypass for: " + funcName + C.RESET);
                    
                    var spoofVal = ptr("-1");

                    if (funcName === "fopen") {
                        // BUG: Open a real, empty file instead of returning NULL (0x0)
                        var fopenPtr = new NativeFunction(getExportSafe("libc.so", "fopen"), 'pointer', ['pointer', 'pointer']);
                        var devNull = Memory.allocUtf8String("/dev/null");
                        var mode = Memory.allocUtf8String("r");
                        spoofVal = fopenPtr(devNull, mode);
                        // Old
                        //spoofVal = ptr("0x0");
                    } else if (funcName === "__system_property_get") {
                        spoofVal = ptr("0x0");
                        try {
                            this.args[1].writeUtf8String("");
                        } catch (e) {}
                    } else if (funcName === "open" || funcName === "openat") {
                        // open/openat return a real fd. If the call already succeeded, replacing
                        // the return with -1 would leak the descriptor, so close it first, then
                        // report ENOENT (set AFTER close, since close() clobbers errno).
                        var realFd = retval.toInt32();
                        if (realFd >= 0) {
                            libcClose(realFd);
                            setErrnoENOENT();
                        }
                    } else if (funcName === "stat" || funcName === "lstat" || funcName === "stat64" ||
                               funcName === "lstat64" || funcName === "newfstatat" || funcName === "statx") {
                        // stat family returns 0 on success; spoof to -1 and report ENOENT so callers
                        // that check errno after a -1 (common in File.exists()/root checks) see a
                        // consistent "file not found" rather than a stale errno.
                        if (retval.toInt32() === 0) setErrnoENOENT();
                    }

                    // retval.replace is always available in onLeave; the old register-write
                    // fallback was dead code and has been removed.
                    try {
                        retval.replace(spoofVal);
                    } catch (e) {
                        console.log(C.RED + "    -> [!] Bypass error: " + e.message + C.RESET);
                    }
                }
            }
        });
        console.log(C.GREEN + "[+] Hooked I/O: " + funcName + C.RESET);
    } catch (e) {
        console.log(C.RED + "[-] Failed to hook I/O " + funcName + ": " + e.message + C.RESET);
    }
}

// ==========================================
// HIGH-PERFORMANCE CMODULE (STRING ASSEMBLY)
// ==========================================

function hookStringsNative() {
    var targetsC = TARGET_STRINGS.map(function(s) { return '"' + s.toLowerCase() + '"'; }).join(", ");
    
    var cCode = `
    #include <gum/guminterceptor.h>
    #include <string.h>

    extern void onMatch(const char *str, const char *funcName, void *returnAddress);

    const char *targets[] = { ` + targetsC + ` };
    const int num_targets = ` + TARGET_STRINGS.length + `;

    // cap: destination buffer size. -1 = unbounded (sprintf always NUL-terminates on success);
    // for snprintf it is the caller's size argument, so cap == 0 means dest was never written.
    typedef struct { const char *dest; long cap; } SprintfState;

    // Case-insensitive substring search, implemented inline: Frida's CModule (TinyCC) cannot link
    // libc strcasestr on Android (undefined symbol at link time). This scans the FULL, unbounded
    // string with no fixed buffer and no in-place mutation of the (possibly read-only) source.
    // targets[] are already lowercased on the JS side.
    static int ci_contains(const char *hay, const char *needle) {
        if (!hay || !needle || !*needle) return 0;
        for (; *hay; hay++) {
            const char *h = hay;
            const char *n = needle;
            while (*h && *n) {
                char ch = *h;
                char cn = *n;
                if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
                if (cn >= 'A' && cn <= 'Z') cn = (char)(cn + 32);
                if (ch != cn) break;
                h++; n++;
            }
            if (!*n) return 1;
        }
        return 0;
    }

    static void scan_and_report(const char *src, const char *funcName, GumInvocationContext *ic) {
        if (!src) return;
        for (int i = 0; i < num_targets; i++) {
            if (ci_contains(src, targets[i])) {
                void *retAddr = gum_invocation_context_get_return_address(ic);
                onMatch(src, funcName, retAddr);
                return;
            }
        }
    }

    // strcpy/strcat: the source argument (arg 1) already holds the final substring.
    void on_strcpy(GumInvocationContext *ic) {
        scan_and_report((const char *) gum_invocation_context_get_nth_argument(ic, 1), "strcpy", ic);
    }
    void on_strcat(GumInvocationContext *ic) {
        scan_and_report((const char *) gum_invocation_context_get_nth_argument(ic, 1), "strcat", ic);
    }

    // sprintf/snprintf: the ASSEMBLED output lives in the destination buffer (arg 0), only valid
    // AFTER the call. Capture dest (+ snprintf's size) on enter, scan on leave. Guard against a
    // never-written destination (snprintf size 0, or a negative return) to avoid an OOB read.
    static void scan_output(GumInvocationContext *ic, const char *funcName) {
        SprintfState *s = (SprintfState *) gum_invocation_context_get_listener_invocation_data(ic, sizeof(SprintfState));
        int ret = (int) (size_t) gum_invocation_context_get_return_value(ic);
        if (ret < 0) return;      // encoding error: destination contents are indeterminate
        if (s->cap == 0) return;  // snprintf(dest, 0, ...): destination was never touched
        scan_and_report(s->dest, funcName, ic);
    }
    void on_sprintf_enter(GumInvocationContext *ic) {
        SprintfState *s = (SprintfState *) gum_invocation_context_get_listener_invocation_data(ic, sizeof(SprintfState));
        s->dest = (const char *) gum_invocation_context_get_nth_argument(ic, 0);
        s->cap = -1;
    }
    void on_sprintf_leave(GumInvocationContext *ic) { scan_output(ic, "sprintf"); }
    void on_snprintf_enter(GumInvocationContext *ic) {
        SprintfState *s = (SprintfState *) gum_invocation_context_get_listener_invocation_data(ic, sizeof(SprintfState));
        s->dest = (const char *) gum_invocation_context_get_nth_argument(ic, 0);
        s->cap = (long) gum_invocation_context_get_nth_argument(ic, 1);
    }
    void on_snprintf_leave(GumInvocationContext *ic) { scan_output(ic, "snprintf"); }

    // Stability guard for strstr: buggy graphics/emulator code (e.g. libEGL calling
    // strstr(eglQueryString(...)==NULL, needle)) and some malware call strstr with a NULL
    // argument, which crashes libc (NULL deref in strchr). Point any NULL argument at a static
    // empty string so the call returns safely (NULL / haystack) instead of faulting.
    static const char EMPTY_STR[1] = { 0 };
    void guard_strstr(GumInvocationContext *ic) {
        if (gum_invocation_context_get_nth_argument(ic, 0) == 0)
            gum_invocation_context_replace_nth_argument(ic, 0, (gpointer) EMPTY_STR);
        if (gum_invocation_context_get_nth_argument(ic, 1) == 0)
            gum_invocation_context_replace_nth_argument(ic, 1, (gpointer) EMPTY_STR);
    }
    `;

    try {
        var cm = new CModule(cCode, {
            onMatch: new NativeCallback(function(strPtr, funcPtr, retAddr) {
                if (!isTargetCaller(retAddr)) return;
                var str = readStrSafe(strPtr);
                var func = readStrSafe(funcPtr);
                // No valid Interceptor CpuContext inside a CModule NativeCallback; attribute the
                // call via the explicitly-passed return address instead of an unreliable backtrace.
                var site = "";
                try { site = DebugSymbol.fromAddress(retAddr).toString(); } catch (e) {}
                checkAndLog("[CModule] " + func + (site ? " @ " + site : ""), str, null);
            }, 'void', ['pointer', 'pointer', 'pointer'])
        });

        var handlers = {
            "strcpy":   { onEnter: cm.on_strcpy },
            "strcat":   { onEnter: cm.on_strcat },
            "sprintf":  { onEnter: cm.on_sprintf_enter, onLeave: cm.on_sprintf_leave },
            "snprintf": { onEnter: cm.on_snprintf_enter, onLeave: cm.on_snprintf_leave }
        };
        Object.keys(handlers).forEach(function(fn) {
            var p = getExportSafe("libc.so", fn);
            if (p) Interceptor.attach(p, handlers[fn]);
        });

        // Stability guard: protect strstr against NULL arguments (a libc NULL-deref crash seen
        // when the emulator's libEGL calls strstr on a NULL extension string). Native onEnter,
        // so no per-call JS overhead on this very hot function.
        try {
            var strstrPtr = getExportSafe("libc.so", "strstr");
            if (strstrPtr && cm.guard_strstr) {
                // BUG: Commented out to to stop crashing libEGL!
                Interceptor.attach(strstrPtr, { onEnter: cm.guard_strstr });
                console.log(C.GREEN + "[+] Installed strstr NULL-argument guard" + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not install strstr guard: " + e.message + C.RESET);
        }

        console.log(C.GREEN + "[+] Native CModule injected for high-performance string matching." + C.RESET);
    } catch(e) {
        console.log(C.RED + "[-] Failed to compile CModule string hooks: " + e.message + C.RESET);
    }
}

// ==========================================
// JNI BINDING & ENVIRONMENT HOOKS
// ==========================================

function hookLibart() {
    var exports = [];
    try { exports = Process.getModuleByName("libart.so").enumerateExports(); } catch(e) { return; }
    
    var hookedFindClass = false, hookedRegisterNatives = false;
    
    for (var i = 0; i < exports.length; i++) {
        var name = exports[i].name;
        
        if (!hookedRegisterNatives && name.indexOf("RegisterNatives") !== -1 && name.indexOf("JNI") !== -1 && name.indexOf("CheckJNI") === -1) {
            try {
                Interceptor.attach(exports[i].address, {
                    onEnter: function (args) {
                        if (!isTargetCaller(this.returnAddress)) return;
                        var env = args[0], clazz = args[1], methodsPtr = args[2], methodCount = args[3].toInt32();
                        
                        console.log("\n" + C.PURPLE + "[+] [JNI] RegisterNatives Triggered! Binding " + methodCount + " methods." + C.RESET);
                        
                        for (var j = 0; j < methodCount; j++) {
                            var offset = j * Process.pointerSize * 3;
                            var namePtr = methodsPtr.add(offset).readPointer();
                            var sigPtr = methodsPtr.add(offset + Process.pointerSize).readPointer();
                            var fnPtr = methodsPtr.add(offset + (Process.pointerSize * 2)).readPointer();
                            
                            var mName = readStrSafe(namePtr);
                            var sig = readStrSafe(sigPtr);
                            var mod = Process.findModuleByAddress(fnPtr);
                            var modName = mod ? mod.name : "Unknown Module";
                            
                            console.log(C.YELLOW + "    -> " + mName + sig + " => " + fnPtr + " (" + modName + ")" + C.RESET);
                            checkAndLog("RegisterNatives Name", mName, null);
                        }
                    }
                });
                hookedRegisterNatives = true;
                console.log(C.GREEN + "[+] Hooked JNI Runtime: RegisterNatives" + C.RESET);
            } catch(e) { console.log(C.YELLOW + "[-] RegisterNatives hook failed: " + e.message + C.RESET); }
        }
        
        if (!hookedFindClass && name.indexOf("JNI") !== -1 && name.indexOf("FindClass") !== -1 && name.indexOf("CheckJNI") === -1) {
            try {
                Interceptor.attach(exports[i].address, {
                    onEnter: function (args) { 
                        if (!isTargetCaller(this.returnAddress)) return;
                        var ctx = this.context;
                        checkAndLog("JNI FindClass", readStrSafe(args[1]), function() { return getNativeBacktrace(ctx); }); 
                    }
                });
                hookedFindClass = true;
            } catch(e) { console.log(C.YELLOW + "[-] FindClass hook failed: " + e.message + C.RESET); }
        }
    }
}

// ==========================================
// JNI BINDING & ENVIRONMENT HOOKS (UNIVERSAL FIX)
// ==========================================
function hookJNIEnv() {
    if (!Java.available) return;

    Java.perform(function () {
        try {
            var env = Java.vm.getEnv();
            if (!env || !env.handle) {
                console.log(C.YELLOW + "[-] JNIEnv handle not available." + C.RESET);
                return;
            }

            // Use the instance method NativePointer.readPointer(); the static Memory.readPointer()
            // was REMOVED in Frida 17, and would throw here (silently disabling every JNIEnv hook).
            var envPtr = ptr(env.handle);
            var vtable = envPtr.readPointer();
            var pSize = Process.pointerSize;

            // Standard JNIEnv function-table indices (jni.h): GetMethodID=33,
            // GetStaticMethodID=113, NewStringUTF=167, GetStringUTFChars=169.
            var getMethodIdPtr = vtable.add(33 * pSize).readPointer();
            var getStaticMethodIdPtr = vtable.add(113 * pSize).readPointer();
            var newStringUtfPtr = vtable.add(167 * pSize).readPointer();
            var getStringUtfCharsPtr = vtable.add(169 * pSize).readPointer();

            function hookJniMethod(ptrAddress, name, type) {
                if (!ptrAddress || ptrAddress.isNull()) {
                    console.log(C.YELLOW + "[-] Cannot resolve pointer for JNI " + name + C.RESET);
                    return;
                }

                try {
                    Interceptor.attach(ptrAddress, {
                        onEnter: function (args) {
                            this.retAddr = this.returnAddress;
                            this.myCtx = this.context;
                            if (!isTargetCaller(this.retAddr)) { this.skip = true; return; }
                            this.skip = false;
                            
                            // Capture the context into a local; inside the trace closures below
                            // `this` is NOT the Interceptor context (checkAndLog calls them bare).
                            var ctx = this.myCtx;
                            if (type === "method") {
                                var nameStr = readStrSafe(args[2]);
                                var sigStr = readStrSafe(args[3]);
                                checkAndLog("JNI " + name, nameStr + sigStr, function() { return getNativeBacktrace(ctx); });
                            } else if (type === "newstring") {
                                var str = readStrSafe(args[1]);
                                checkAndLog("JNI " + name, str, function() { return getNativeBacktrace(ctx); });
                            }
                        },
                        onLeave: function (retval) {
                            if (this.skip || retval.isNull()) return;
                            if (type === "getstring") {
                                var str = readStrSafe(retval);
                                var ctx = this.myCtx;
                                checkAndLog("JNI " + name, str, function() { return getNativeBacktrace(ctx); });
                            }
                        }
                    });
                } catch(e) {
                    console.log(C.YELLOW + "[-] Failed hooking JNI " + name + ": " + e.message + C.RESET);
                }
            }

            hookJniMethod(getMethodIdPtr, "GetMethodID", "method");
            hookJniMethod(getStaticMethodIdPtr, "GetStaticMethodID", "method");
            hookJniMethod(newStringUtfPtr, "NewStringUTF", "newstring");
            hookJniMethod(getStringUtfCharsPtr, "GetStringUTFChars", "getstring");
            
            console.log(C.GREEN + "[+] Hooked core JNIEnv APIs successfully." + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook JNIEnv vtable: " + e.message + C.RESET);
        }
    });
}

// ==========================================
// EXTENDED COVERAGE HOOKS
// ==========================================

// Detection-only path/string hook (never spoofs). For high-frequency functions where an
// active bypass would break the app (dlopen/dlsym/getenv), we only observe and match.
// Dedup set of already-attached export addresses: dlopen/android_dlopen_ext/dlsym resolve to the
// SAME function in both libdl.so and libc.so (libc re-exports them), so per-module attaching would
// otherwise double-hook one function (duplicate alerts + double overhead on a symbol-resolution path).
var _detectAttached = {};

function safeAttachDetect(moduleName, funcName, argIndex) {
    var ptrAddress = getExportSafe(moduleName, funcName);
    if (!ptrAddress) return;
    var addrKey = ptrAddress.toString();
    if (_detectAttached[addrKey]) return; // already hooked this exact function via another module
    _detectAttached[addrKey] = true;
    try {
        Interceptor.attach(ptrAddress, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) return;
                var s = readStrSafe(args[argIndex]);
                if (!s) return;
                var ctx = this.context;
                checkAndLog(funcName, s, function() { return getNativeBacktrace(ctx); });
            }
        });
        console.log(C.GREEN + "[+] Hooked (detect): " + funcName + C.RESET);
    } catch (e) {
        console.log(C.RED + "[-] Failed to hook " + funcName + ": " + e.message + C.RESET);
    }
}

// Native library loading / symbol resolution and environment probes. Packers and
// second-stage payloads dlopen decrypted .so files without going through Java.
function hookLibraryLoading() {
    ["libdl.so", "libc.so"].forEach(function(mod) {
        safeAttachDetect(mod, "dlopen", 0);
        safeAttachDetect(mod, "android_dlopen_ext", 0);
        safeAttachDetect(mod, "dlsym", 1);
    });
    safeAttachDetect("libc.so", "getenv", 0); // LD_PRELOAD, FRIDA_*, emulator env vars
}

// Raw syscall() dispatcher. Malware often calls syscall(__NR_openat/ptrace/...) directly to
// bypass libc-export hooks. Only arm64 and x86_64 (the common Android ABIs) are covered;
// inlined SVC/int 0x80 instructions still evade this and would need Stalker instrumentation.
function hookRawSyscalls() {
    var sysPtr = getExportSafe("libc.so", "syscall");
    if (!sysPtr) return;

    var TABLES = {
        // arm64 (asm-generic) has no legacy non-*at file syscalls. x86_64 still exposes the
        // legacy open/stat/lstat/access/readlink, which malware can issue directly on an emulator.
        'arm64': { openat: 56, faccessat: 48, newfstatat: 79, statx: 291, readlinkat: 78, execve: 221, ptrace: 117 },
        'x64':   { openat: 257, faccessat: 269, newfstatat: 262, statx: 332, readlinkat: 267, execve: 59, ptrace: 101,
                   open: 2, stat: 4, lstat: 6, access: 21, readlink: 89 }
    };
    var table = TABLES[Process.arch];
    if (!table) {
        console.log(C.YELLOW + "[-] Raw syscall hook: unsupported arch " + Process.arch + C.RESET);
        return;
    }
    var byNum = {};
    Object.keys(table).forEach(function(k) { byNum[table[k]] = k; });

    // When routed through syscall(), all kernel arguments shift by one (args[0] is the number).
    // Path-bearing syscalls place the path at kernel arg1 (args[2]); execve at kernel arg0 (args[1]).
    // Path position in args[] (args[0] is the syscall number). The *at family takes the path as
    // kernel arg1 (args[2]); execve and the legacy non-*at calls take it as kernel arg0 (args[1]).
    var PATH_AT = { openat: 2, faccessat: 2, newfstatat: 2, statx: 2, readlinkat: 2, execve: 1,
                    open: 1, stat: 1, lstat: 1, access: 1, readlink: 1 };

    Interceptor.attach(sysPtr, {
        onEnter: function (args) {
            this.sysName = null;
            if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
            this.skip = false;

            var name = byNum[args[0].toInt32()];
            if (!name) return;
            this.sysName = name;

            if (name === "ptrace") {
                this.isTraceme = args[1].toInt32() === 0; // PTRACE_TRACEME == 0
                return;
            }
            var idx = PATH_AT[name];
            if (idx !== undefined) {
                var path = readStrSafe(args[idx]);
                var ctx = this.context;
                checkAndLog("syscall:" + name, path, function() { return getNativeBacktrace(ctx); });
            }
        },
        onLeave: function (retval) {
            if (this.skip || this.sysName !== "ptrace" || !this.isTraceme) return;
            console.log("\n" + C.PURPLE + "[!] [syscall ptrace] PTRACE_TRACEME via raw syscall detected!" + C.RESET);
            if (ACTIVE_BYPASS) {
                console.log(C.RED + "    -> [BYPASS] Spoofing raw ptrace success (Returning 0)." + C.RESET);
                retval.replace(ptr("0x0"));
            }
        }
    });
    console.log(C.GREEN + "[+] Hooked raw syscall dispatcher (" + Process.arch + ")" + C.RESET);
}

// Java-layer emulator/sandbox detection that never touches the native hooks: Settings.Secure
// keys (adb_enabled, development_settings_enabled), telephony operators, sensor vendors,
// and Battery properties (100% capacity / charging status).
function hookJavaEvasionAPIs() {
    if (!Java.available) return;
    Java.perform(function() {
        ["android.provider.Settings$Secure", "android.provider.Settings$Global"].forEach(function(cls) {
            try {
                var S = Java.use(cls);
                S.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, key) {
                    checkAndLog(cls + ".getString", key, null);
                    return this.getString(cr, key);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook " + cls + ".getString: " + e.message + C.RESET);
            }
        });

        try {
            var TM = Java.use("android.telephony.TelephonyManager");
            ["getSimOperator", "getNetworkOperator", "getSimCountryIso"].forEach(function(m) {
                try {
                    TM[m].overload().implementation = function() {
                        var v = this[m]();
                        console.log(C.PURPLE + "[!] [TELEPHONY] " + m + "() -> " + v + C.RESET);
                        checkAndLog("TelephonyManager." + m, "" + v, null);
                        return v;
                    };
                } catch (e) {}
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook TelephonyManager: " + e.message + C.RESET);
        }

        try {
            var SM = Java.use("android.hardware.SensorManager");
            SM.getDefaultSensor.overload('int').implementation = function(type) {
                var sensor = this.getDefaultSensor(type);
                if (sensor !== null) {
                    try {
                        checkAndLog("SensorManager.getDefaultSensor", sensor.getName() + " / " + sensor.getVendor(), null);
                    } catch (e) {}
                }
                return sensor;
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook SensorManager: " + e.message + C.RESET);
        }

        // ---- NEW: BatteryManager & Intent Checks (Emulator Detection) ----
        try {
            var BatteryManager = Java.use("android.os.BatteryManager");
            
            // Hook direct capacity checks
            BatteryManager.getIntProperty.overload('int').implementation = function(id) {
                var val = this.getIntProperty(id);
                // 4 = BATTERY_PROPERTY_CAPACITY
                if (id === 4) {
                    var sig = "battery_manager_capacity";
                    var seen = !!ALERT_HISTORY[sig];
                    if (!seen) markSeen(sig);

                    if (!seen) {
                        console.log("\n" + C.PURPLE + "[!] [BATTERY] BatteryManager.getIntProperty(CAPACITY) queried" + C.RESET);
                        console.log(C.YELLOW + "    -> Original Value: " + val + "%" + C.RESET);
                    }

                    if (ACTIVE_BYPASS) {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing battery capacity to 83%" + C.RESET);
                        return 83; // Spoof a realistic battery level
                    }
                }
                return val;
            };

            // Hook direct charging status checks
            try {
                BatteryManager.isCharging.overload().implementation = function() {
                    var val = this.isCharging();
                    var sig = "battery_manager_ischarging";
                    var seen = !!ALERT_HISTORY[sig];
                    if (!seen) markSeen(sig);

                    if (!seen) {
                        console.log("\n" + C.PURPLE + "[!] [BATTERY] BatteryManager.isCharging() queried" + C.RESET);
                        console.log(C.YELLOW + "    -> Original Value: " + val + C.RESET);
                    }

                    if (ACTIVE_BYPASS) {
                        if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing isCharging to false" + C.RESET);
                        return false; // Spoof unplugged status
                    }
                    return val;
                };
            } catch(e) {}

        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook BatteryManager: " + e.message + C.RESET);
        }

        // Hook Intent extras (used when registering receivers for ACTION_BATTERY_CHANGED)
        try {
            var Intent = Java.use("android.content.Intent");
            Intent.getIntExtra.overload('java.lang.String', 'int').implementation = function(name, def) {
                var val = this.getIntExtra(name, def);
                
                if (name === "level" || name === "plugged") {
                    var action = "";
                    try { action = this.getAction(); } catch (e) {}
                    
                    if (action === "android.intent.action.BATTERY_CHANGED") {
                        var sig = "battery_intent|" + name;
                        var seen = !!ALERT_HISTORY[sig];
                        if (!seen) markSeen(sig);

                        if (!seen) {
                            console.log("\n" + C.PURPLE + "[!] [BATTERY] Intent.getIntExtra('" + name + "') queried from BATTERY_CHANGED" + C.RESET);
                            console.log(C.YELLOW + "    -> Original Value: " + val + C.RESET);
                        }

                        if (ACTIVE_BYPASS) {
                            if (name === "level") {
                                if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing battery level to 83" + C.RESET);
                                return 83;
                            } else if (name === "plugged") {
                                // 0 = unplugged (running on battery), emulators are usually AC (1) or USB (2)
                                if (!seen) console.log(C.RED + "    -> [BYPASS] Spoofing battery plugged status to 0 (Unplugged)" + C.RESET);
                                return 0; 
                            }
                        }
                    }
                }
                return val;
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook Intent.getIntExtra: " + e.message + C.RESET);
        }

        console.log(C.GREEN + "[+] Hooked Java evasion APIs (Settings, Telephony, Sensors, Battery)" + C.RESET);
    });
}


// ===================== MODULE: jni-extended (hookJNIEnvExtended) =====================
// ==========================================
// EXTENDED JNIENV VTABLE HOOKS
// ==========================================
// Extends the core JNIEnv coverage in hookJNIEnv (which already owns slots 33/113/167/169).
// Every slot below was verified against the canonical JNINativeInterface layout in jni.h:
// 4 reserved pointers precede GetVersion=4, and the anchors this file already trusts line up
// exactly (GetMethodID=33, GetStaticMethodID=113, NewStringUTF=167, GetStringUTFChars=169).
// Confirmed indices: DefineClass=5, ThrowNew=14, ExceptionOccurred=15, GetMethodID=33,
// CallObjectMethod=34, CallBooleanMethodA=39, CallVoidMethod=61, GetFieldID=94,
// GetStaticMethodID=113, CallStaticObjectMethod=114, CallStaticBooleanMethodA=119,
// CallStaticVoidMethod=141, GetStaticFieldID=144, GetByteArrayElements=184,
// GetByteArrayRegion=200, GetStringRegion=220, GetStringUTFRegion=221.
//
// NOTE on the "Boolean" representatives: the Boolean slots hooked here are 39 and 119, which
// are CallBooleanMethodA / CallStaticBooleanMethodA (the jvalue-array form). The plain varargs
// CallBooleanMethod is 37 and CallStaticBooleanMethod is 117 - we intentionally hook the A form
// at 39/119 per the assignment. Object (34/114) and Void (61/141) are the base varargs forms.
// For every Call<Type>Method / CallStatic<Type>Method entry args[0]=JNIEnv, args[1]=jobject/
// jclass, args[2]=jmethodID; we correlate args[2] to the name+sig map built from GetMethodID /
// GetStaticMethodID returns (they return the jmethodID as the retval).

// Bounded jmethodID -> "name+sig" correlation map, populated by GetMethodID/GetStaticMethodID
// onLeave and read by the Call*Method hooks. Bounded like ALERT_HISTORY so a long-running sample
// that resolves thousands of methods cannot grow it without limit.
var JNI_METHOD_MAP = {};
var JNI_METHOD_MAP_SIZE = 0;
var JNI_METHOD_MAP_CAP = 4000;

// Upper bound on how many code units we will read out of a GetString*Region destination buffer.
// jsize len is attacker-influenced; a bogus/huge value must not drive a multi-MB read.
var JNI_REGION_READ_CAP = 8192;

function jniRememberMethod(idPtr, name, sig) {
    try {
        if (!idPtr || idPtr.isNull()) return;
        var key = idPtr.toString();
        if (JNI_METHOD_MAP.hasOwnProperty(key)) return;
        // Stop growing once full rather than wiping+refilling: a churn-heavy app would otherwise
        // repeatedly clear the map and re-read/re-insert on every GetMethodID (a hot path). A stale
        // full map is fine - it only supplies best-effort name labels for the Call* hooks.
        if (JNI_METHOD_MAP_SIZE >= JNI_METHOD_MAP_CAP) return;
        JNI_METHOD_MAP[key] = (name || "?") + (sig || "");
        JNI_METHOD_MAP_SIZE++;
    } catch (e) {}
}

function jniLookupMethod(idPtr) {
    try {
        if (!idPtr || idPtr.isNull()) return null;
        return JNI_METHOD_MAP[idPtr.toString()] || null;
    } catch (e) { return null; }
}

function hookJNIEnvExtended() {
    if (!Java.available) {
        console.log(C.YELLOW + "[-] Java is not available. Skipping extended JNIEnv hooks." + C.RESET);
        return;
    }

    Java.perform(function () {
        try {
            var env = Java.vm.getEnv();
            if (!env || !env.handle) {
                console.log(C.YELLOW + "[-] JNIEnv handle not available (extended)." + C.RESET);
                return;
            }

            // Resolve the vtable exactly like hookJNIEnv: envPtr -> readPointer() -> function table.
            // NativePointer.readPointer() (Frida 16/17); the static Memory.readPointer() was removed.
            var envPtr = ptr(env.handle);
            var vtable = envPtr.readPointer();
            var pSize = Process.pointerSize;

            // Guarded slot read: returns null (never throws) if the slot pointer is null so callers
            // can skip that hook rather than tearing down the whole install.
            function slot(index) {
                try {
                    var p = vtable.add(index * pSize).readPointer();
                    if (!p || p.isNull()) return null;
                    return p;
                } catch (e) { return null; }
            }

            // Generic attach helper: skips a null slot and wraps Interceptor.attach in try/catch
            // so one bad slot cannot abort the rest.
            function attachSlot(index, name, callbacks) {
                var p = slot(index);
                if (!p) {
                    console.log(C.YELLOW + "[-] JNIEnv slot " + index + " (" + name + ") null - skipped." + C.RESET);
                    return;
                }
                try {
                    Interceptor.attach(p, callbacks);
                    console.log(C.GREEN + "[+] Hooked JNIEnv " + name + " (slot " + index + ")" + C.RESET);
                } catch (e) {
                    console.log(C.YELLOW + "[-] Failed hooking JNIEnv " + name + " (slot " + index + "): " + e.message + C.RESET);
                }
            }

            // ---- GetStringUTFRegion (221) / GetStringRegion (220) ----
            // jint GetStringUTFRegion(env, jstring, jsize start, jsize len, char* buf)
            // -> args[0]=env, args[1]=jstring, args[2]=start, args[3]=len, args[4]=dest buffer.
            // The dest buffer is only populated AFTER the call: capture dest+len onEnter, read+scan
            // onLeave. Gated by isTargetCaller so we only inspect calls from target modules, and
            // the read length is clamped to JNI_REGION_READ_CAP so a bogus len cannot drive a huge read.
            attachSlot(221, "GetStringUTFRegion", {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.dest = args[4];
                    var n = args[3].toInt32();
                    this.len = (n > JNI_REGION_READ_CAP) ? JNI_REGION_READ_CAP : n;
                    this.myCtx = this.context;
                },
                onLeave: function () {
                    if (this.skip || !this.dest || this.dest.isNull() || this.len <= 0) return;
                    // GetStringUTFRegion writes modified-UTF-8; read at most len bytes (safe upper bound).
                    // args[3] is a CHARACTER count but readUtf8String wants a BYTE count; modified
                    // UTF-8 is up to 3 bytes/char (BMP), so read a 3x window (capped) to avoid
                    // slicing a multi-byte sequence mid-character.
                    var s = readStrSafe(this.dest, Math.min(this.len * 3, JNI_REGION_READ_CAP));
                    if (!s) return;
                    var ctx = this.myCtx;
                    checkAndLog("JNI GetStringUTFRegion", s, function () { return getNativeBacktrace(ctx); });
                }
            });
            // GetStringRegion writes UTF-16 (jchar*) into dest; decode with readUtf16String(len).
            attachSlot(220, "GetStringRegion", {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.dest = args[4];
                    var n = args[3].toInt32();
                    this.len = (n > JNI_REGION_READ_CAP) ? JNI_REGION_READ_CAP : n;
                    this.myCtx = this.context;
                },
                onLeave: function () {
                    if (this.skip || !this.dest || this.dest.isNull() || this.len <= 0) return;
                    var s = "";
                    try { s = this.dest.readUtf16String(this.len) || ""; } catch (e) { s = ""; }
                    if (!s) return;
                    var ctx = this.myCtx;
                    checkAndLog("JNI GetStringRegion", s, function () { return getNativeBacktrace(ctx); });
                }
            });

            // ---- GetByteArrayElements (184) / GetByteArrayRegion (200) ----
            // These surface decrypted DEX/ELF/ZIP payloads that never touch libc file I/O.
            // GetByteArrayElements(env, jbyteArray, jboolean* isCopy) -> retval = jbyte* buffer.
            // We do not know the array length here, so only act when the first bytes match a known
            // payload magic (payloadMagic reads just 4 bytes, fault-guarded) and hand a fixed preview
            // window to dumpBuffer (which caps and fault-guards its own reads). Gated by caller and by
            // magic so benign byte arrays (every String.getBytes(), etc.) never flood.
            var BA_PREVIEW = 4096;
            attachSlot(184, "GetByteArrayElements", {
                onEnter: function (args) {
                    this.skip = !isTargetCaller(this.returnAddress);
                },
                onLeave: function (retval) {
                    if (this.skip || !retval || retval.isNull()) return;
                    try {
                        var magic = payloadMagic(retval);
                        if (magic) {
                            dumpBuffer("JNI_GetByteArrayElements_" + magic, retval, BA_PREVIEW);
                        }
                    } catch (e) {}
                }
            });
            // GetByteArrayRegion(env, jbyteArray, jsize start, jsize len, jbyte* buf) copies into
            // args[4]; length is known (args[3]) and the buffer is filled AFTER the call.
            attachSlot(200, "GetByteArrayRegion", {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.dest = args[4];
                    this.len = args[3].toInt32();
                },
                onLeave: function () {
                    if (this.skip || !this.dest || this.dest.isNull() || this.len <= 0) return;
                    try {
                        var magic = payloadMagic(this.dest);
                        if (magic) {
                            dumpBuffer("JNI_GetByteArrayRegion_" + magic, this.dest, this.len);
                        }
                    } catch (e) {}
                }
            });

            // ---- GetMethodID (33) / GetStaticMethodID (113): map builders ----
            // These are ALSO hooked in hookJNIEnv for detection; here we attach an INDEPENDENT
            // listener (Interceptor allows multiple listeners per address) that ONLY records
            // jmethodID -> name+sig into JNI_METHOD_MAP (no detection, no spoof), so the Call*Method
            // hooks below can resolve the method being invoked. Deliberately NOT gated by
            // isTargetCaller: the map must be complete regardless of resolver, or Call* lookups miss.
            // GetMethodID(env, clazz, char* name, char* sig) -> retval = jmethodID.
            function attachMethodIdMapper(index, label) {
                attachSlot(index, label + " (map)", {
                    onEnter: function (args) {
                        this.mName = readStrSafe(args[2]);
                        this.mSig = readStrSafe(args[3]);
                    },
                    onLeave: function (retval) {
                        jniRememberMethod(retval, this.mName, this.mSig);
                    }
                });
            }
            attachMethodIdMapper(33, "GetMethodID");
            attachMethodIdMapper(113, "GetStaticMethodID");

            // ---- Call<Type>Method + CallStatic<Type>Method representatives ----
            // Representative slots: Object=34/114, Void=61/141, Boolean=39/119 (39/119 are the
            // CallBooleanMethodA / CallStaticBooleanMethodA jvalue-array forms). args[2] = jmethodID;
            // resolve it against JNI_METHOD_MAP and run the resolved "name+sig" through checkAndLog so
            // evasive reflective-style native dispatch is caught. Gated by isTargetCaller AND by a
            // successful map lookup, so these very hot slots stay quiet unless there is real signal.
            function attachCallHook(index, label) {
                attachSlot(index, label, {
                    onEnter: function (args) {
                        if (!isTargetCaller(this.returnAddress)) return;
                        var resolved = jniLookupMethod(args[2]);
                        if (!resolved) return; // no signal without a known name+sig
                        var ctx = this.context;
                        checkAndLog("JNI " + label, resolved, function () { return getNativeBacktrace(ctx); });
                    }
                });
            }
            attachCallHook(34, "CallObjectMethod");
            attachCallHook(114, "CallStaticObjectMethod");
            attachCallHook(61, "CallVoidMethod");
            attachCallHook(141, "CallStaticVoidMethod");
            attachCallHook(39, "CallBooleanMethodA");
            attachCallHook(119, "CallStaticBooleanMethodA");

            // ---- GetFieldID (94) / GetStaticFieldID (144): name + sig ----
            // GetFieldID(env, clazz, char* name, char* sig). Detection-only on name+sig.
            function attachFieldId(index, label) {
                attachSlot(index, label, {
                    onEnter: function (args) {
                        if (!isTargetCaller(this.returnAddress)) return;
                        var fName = readStrSafe(args[2]);
                        var fSig = readStrSafe(args[3]);
                        if (!fName && !fSig) return;
                        var ctx = this.context;
                        checkAndLog("JNI " + label, fName + fSig, function () { return getNativeBacktrace(ctx); });
                    }
                });
            }
            attachFieldId(94, "GetFieldID");
            attachFieldId(144, "GetStaticFieldID");

            // ---- DefineClass (5) ----
            // DefineClass(env, char* name, jobject loader, jbyte* buf, jsize len) - args[1]=name,
            // args[3]=class-bytes buffer, args[4]=len. This is in-memory class injection: dump the
            // buffer (dumpBuffer honours DUMP_PAYLOADS) and scan the class name via checkAndLog.
            attachSlot(5, "DefineClass", {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var name = readStrSafe(args[1]);
                    var buf = args[3];
                    var len = 0;
                    try { len = args[4].toInt32(); } catch (e) { len = 0; }
                    var ctx = this.context;
                    if (name) {
                        checkAndLog("JNI DefineClass", name, function () { return getNativeBacktrace(ctx); });
                    }
                    if (buf && !buf.isNull() && len > 0) {
                        try { dumpBuffer("JNI_DefineClass_" + (name || "class"), buf, len); } catch (e) {}
                    }
                }
            });

            // ---- ThrowNew (14) / ExceptionOccurred (15) ----
            // ThrowNew(env, jclass, char* message) - args[2]=message string. Anti-analysis code
            // frequently throws with revealing messages ("frida detected", "emulator", ...).
            attachSlot(14, "ThrowNew", {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var msg = readStrSafe(args[2]);
                    if (!msg) return;
                    var ctx = this.context;
                    checkAndLog("JNI ThrowNew", msg, function () { return getNativeBacktrace(ctx); });
                }
            });
            // ExceptionOccurred(env) takes no string args; log occurrences (deduped by call site) as a
            // weak anti-analysis signal from target callers only, so a hot exception-check loop cannot
            // flood the console.
            attachSlot(15, "ExceptionOccurred", {
                onEnter: function () {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var site = "";
                    try { site = DebugSymbol.fromAddress(this.returnAddress).toString(); } catch (e) {}
                    var signature = "JNI ExceptionOccurred|" + site;
                    if (ALERT_HISTORY[signature]) return;
                    markSeen(signature);
                    console.log(C.PURPLE + "[!] [JNI ExceptionOccurred] from " + (site || this.returnAddress) + C.RESET);
                }
            });

            console.log(C.GREEN + "[+] Extended JNIEnv vtable hooks installed." + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to install extended JNIEnv hooks: " + e.message + C.RESET);
        }
    });
}

// ===================== MODULE: art-dex-loaders (hookArtDexLoaders) =====================
// ==========================================
// ART-INTERNAL DEX LOADERS + JNI_OnLoad (PACKER-PROOF)
// ==========================================
//
// Survives Java-DCL bypass: packers that decrypt a dex in memory and feed it
// straight to the ART DexFileLoader never touch dalvik.system.*ClassLoader, so
// hookJavaDCL() misses them. We hook the native libart.so entry points that ALL
// dex loading funnels through (in-memory + file-path), plus per-module JNI_OnLoad.
//
// Does NOT duplicate hookLibart() (RegisterNatives / FindClass) or hookJavaDCL().
// NOTE: dlopen/android_dlopen_ext are ALSO attached by hookLibraryLoading() for
// string detection. Frida stacks independent listeners on the same address, so
// attaching again here (for JNI_OnLoad discovery only) is safe and intentional.

// Small local helper: given a base pointer + a claimed size, decide whether the
// buffer really looks like a dex/cdex payload and, if so, report + dump it once.
// Uses shared payloadMagic()/dumpBuffer(); dedups on (tag|base|magic|len) via ALERT_HISTORY.
function reportArtDexBuffer(tag, basePtr, size, ctx) {
    try {
        if (basePtr == null || basePtr.isNull()) return false;
        var magic = payloadMagic(basePtr);
        // Only act on genuine dex/cdex magic - avoids dumping garbage when a
        // symbol's real signature does not match our (base,size) guess.
        if (magic !== "dex" && magic !== "cdex") return false;

        var len = 0;
        try { len = size ? size.toInt32() : 0; } catch (e) { len = 0; }
        // Sanity-bound the length; ART dex regions are well under this cap.
        if (len < 8 || len > 64 * 1024 * 1024) len = 0;

        var signature = "artdex|" + tag + "|" + basePtr + "|" + magic + "|" + len;
        if (ALERT_HISTORY[signature]) return true;
        markSeen(signature);

        console.log("\n" + C.PURPLE + "[!] [ART-DEX] In-memory dex load via " + tag + C.RESET);
        console.log(C.YELLOW + "    -> base=" + basePtr + " size=" + len + " magic=" + magic + C.RESET);
        try { console.log(C.YELLOW + "    -> preview: " + hexPreview(basePtr, 16) + C.RESET); } catch (e) {}

        // dumpBuffer writes to DUMP_DIR only when DUMP_PAYLOADS is set; otherwise
        // it just logs magic+size+preview. It no-ops on len <= 0, so an untrusted
        // size still gets logged above without dumping garbage.
        try { dumpBuffer("art-dex", basePtr, len); } catch (e) {
            console.log(C.YELLOW + "    -> dumpBuffer failed: " + e.message + C.RESET);
        }

        var bt = getNativeBacktrace(ctx);
        if (bt) console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(bt) + C.RESET);
        return true;
    } catch (e) {
        console.log(C.YELLOW + "[-] reportArtDexBuffer error: " + e.message + C.RESET);
        return false;
    }
}

// Attach to JNI_OnLoad of a single module (if it exports one) so we log the exact
// owning library + backtrace the moment ART invokes native init - the classic place
// a packer stub kicks off. Dedups per module so re-enumeration never double-hooks.
function attachJniOnLoad(modName) {
    try {
        if (!modName) return;
        var sig = "jnionload|" + modName;
        if (ALERT_HISTORY[sig]) return;

        var p = getExportSafe(modName, "JNI_OnLoad");
        if (!p || p.isNull()) return;

        // Mark before attaching so a throw inside attach still records the module
        // (prevents a broken module from being retried on every dlopen).
        markSeen(sig);
        var onLoadPtr = p;
        Interceptor.attach(onLoadPtr, {
            onEnter: function (args) {
                // JNI_OnLoad(JavaVM*, void*): no cheap path/string here, so this is
                // detection-only and low frequency (once per library init). No gating
                // beyond the per-module dedup above is needed.
                var ctx = this.context;
                var bt = getNativeBacktrace(ctx);
                console.log("\n" + C.PURPLE + "[!] [JNI_OnLoad] Native init invoked in: " + modName + C.RESET);
                console.log(C.YELLOW + "    -> JNI_OnLoad @ " + onLoadPtr + C.RESET);
                if (bt) console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(bt) + C.RESET);
            }
        });
        console.log(C.GREEN + "[+] Hooked JNI_OnLoad in " + modName + C.RESET);
    } catch (e) {
        console.log(C.YELLOW + "[-] attachJniOnLoad(" + modName + ") failed: " + e.message + C.RESET);
    }
}

function hookArtDexLoaders() {
    // ---- 1. ART-internal in-memory dex loaders (packer-proof) ----------------
    //
    // Robust to symbol-name variation across Android versions: we scan BOTH exports
    // and (mangled, internal) symbols of libart.so, matching by substring. Names of
    // interest carry "DexFile" together with one of the Open* / loader variants:
    //   - OpenMemory / OpenCommon (pre-Q internal Art::DexFile::Open*)
    //   - ArtDexFileLoader::Open* (Q+ moved loading into DexFileLoader)
    //   - openInMemoryDexFile* (JNI-facing DexFile bridge)
    // These take a const uint8_t* base and a size_t size among their args, but the
    // exact ARG INDEX varies by version/overload, so instead of trusting a fixed
    // index we probe the first several pointer args for real dex/cdex magic and use
    // the following arg as the candidate size. Wrapped per-symbol in try/catch.
    var hookedNames = [];
    var seenAddr = {};

    function looksLikeDexLoader(name) {
        if (!name) return false;
        if (name.indexOf("DexFile") === -1) return false;
        if (name.indexOf("CheckJNI") !== -1) return false;
        return name.indexOf("OpenMemory") !== -1 ||
               name.indexOf("OpenCommon") !== -1 ||
               name.indexOf("openInMemoryDexFile") !== -1 ||
               name.indexOf("ArtDexFileLoader") !== -1;
    }

    function attachDexLoader(name, address) {
        if (!address || address.isNull()) return;
        var key = "" + address;
        if (seenAddr[key]) return;
        seenAddr[key] = true;
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    // libart internal - gate on target caller so framework dex
                    // loading (system apps, GMS) does not flood the log.
                    if (!isTargetCaller(this.returnAddress)) return;
                    var ctx = this.context;
                    // Probe the first few pointer args for dex/cdex magic; the size
                    // is conventionally the arg immediately after the base pointer.
                    // We stop at the first arg whose bytes carry a real magic.
                    for (var k = 0; k < 6; k++) {
                        var basePtr;
                        try { basePtr = args[k]; } catch (e) { break; }
                        if (basePtr == null || basePtr.isNull()) continue;
                        var m;
                        try { m = payloadMagic(basePtr); } catch (e) { m = null; }
                        if (m === "dex" || m === "cdex") {
                            var sizeArg = null;
                            try { sizeArg = args[k + 1]; } catch (e) { sizeArg = null; }
                            if (reportArtDexBuffer(name, basePtr, sizeArg, ctx)) return;
                        }
                    }
                }
            });
            hookedNames.push(name);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook ART loader " + name + ": " + e.message + C.RESET);
        }
    }

    try {
        var libart = Process.getModuleByName("libart.so");

        // Exports first (cheap), then the full symbol table (mangled internals).
        try {
            libart.enumerateExports().forEach(function (exp) {
                if (exp.type === "function" && looksLikeDexLoader(exp.name)) {
                    attachDexLoader(exp.name, exp.address);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] libart export enumeration failed: " + e.message + C.RESET);
        }
        try {
            libart.enumerateSymbols().forEach(function (sym) {
                if (sym.address && !sym.address.isNull() && looksLikeDexLoader(sym.name)) {
                    attachDexLoader(sym.name, sym.address);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] libart symbol enumeration failed: " + e.message + C.RESET);
        }

        if (hookedNames.length > 0) {
            console.log(C.GREEN + "[+] Hooked " + hookedNames.length +
                        " ART in-memory dex loader(s): " + hookedNames.join(", ") + C.RESET);
        } else {
            console.log(C.YELLOW + "[-] No ART in-memory dex loader symbols matched on this build." + C.RESET);
        }
    } catch (e) {
        console.log(C.YELLOW + "[-] hookArtDexLoaders: libart.so unavailable: " + e.message + C.RESET);
    }

    // ---- 2. Exported DexFile_openDexFileNative (file-path dex loading) --------
    // This is the JNI-registered entry behind DexPathList; catches on-disk dex/apk
    // paths even when the Java DexClassLoader hook is bypassed via reflection.
    try {
        var openNativeName = "DexFile_openDexFileNative";
        var libart2 = Process.getModuleByName("libart.so");
        var openNativePtr = null;
        // Exported name is decorated on some builds; match by substring over exports.
        libart2.enumerateExports().forEach(function (exp) {
            if (openNativePtr) return;
            if (exp.type === "function" && exp.name.indexOf("openDexFileNative") !== -1) {
                openNativePtr = exp.address;
                openNativeName = exp.name;
            }
        });
        if (openNativePtr) {
            Interceptor.attach(openNativePtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var ctx = this.context;
                    // Signature: (JNIEnv*, jclass, jstring sourceName, jstring outputName, ...)
                    // The jstring args are Java String objects, not char*; we cannot
                    // readUtf8String them directly, so we log the invocation + backtrace
                    // and let the Java DCL / file I/O hooks surface the actual path.
                    console.log("\n" + C.PURPLE + "[!] [ART-DEX] " + openNativeName +
                                " invoked (file/path dex load)" + C.RESET);
                    var bt = getNativeBacktrace(ctx);
                    if (bt) console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(bt) + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked ART file loader: " + openNativeName + C.RESET);
        } else {
            console.log(C.YELLOW + "[-] DexFile_openDexFileNative not exported on this build." + C.RESET);
        }
    } catch (e) {
        console.log(C.YELLOW + "[-] Failed to hook DexFile_openDexFileNative: " + e.message + C.RESET);
    }

    // ---- 3. JNI_OnLoad per module (existing + newly loaded) ------------------
    // Hook JNI_OnLoad of every currently-mapped module, then hook the dlopen family
    // (onLeave) to catch libraries loaded LATER - a decrypted packer stage - and
    // attach to its JNI_OnLoad the moment it appears. Detection-only, never spoofs.
    try {
        Process.enumerateModules().forEach(function (m) {
            attachJniOnLoad(m.name);
        });
    } catch (e) {
        console.log(C.YELLOW + "[-] JNI_OnLoad module enumeration failed: " + e.message + C.RESET);
    }

    // GATING NOTE: dlopen/android_dlopen_ext only fire on library loads (not a hot
    // path), so no content gating is needed beyond the per-module ALERT_HISTORY
    // dedup inside attachJniOnLoad. hookLibraryLoading() also attaches here for
    // string detection; Frida stacks listeners, so this second attach is fine.
    ["libdl.so", "libc.so"].forEach(function (mod) {
        ["dlopen", "android_dlopen_ext"].forEach(function (fn) {
            try {
                var p = getExportSafe(mod, fn);
                if (!p) return;
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        // arg0 is the filename for both dlopen and android_dlopen_ext.
                        this.reqPath = readStrSafe(args[0]);
                    },
                    onLeave: function (retval) {
                        if (retval.isNull()) return;
                        try {
                            // Resolve the just-loaded module. On Android, dlopen returns
                            // an opaque soinfo* HANDLE, NOT the module's load base, so
                            // findModuleByAddress(handle) usually fails - resolve by the
                            // requested basename over the module list first (reliable),
                            // and only fall back to the handle as a best effort.
                            var attached = false;
                            if (this.reqPath) {
                                var base = this.reqPath.split("/").pop();
                                if (base) {
                                    Process.enumerateModules().forEach(function (m) {
                                        if (m.name === base) {
                                            attachJniOnLoad(m.name);
                                            attached = true;
                                        }
                                    });
                                }
                            }
                            if (!attached) {
                                var owner = null;
                                try { owner = Process.findModuleByAddress(retval); } catch (e) {}
                                if (owner) attachJniOnLoad(owner.name);
                            }
                        } catch (e) {
                            console.log(C.YELLOW + "[-] post-dlopen JNI_OnLoad resolve failed: " + e.message + C.RESET);
                        }
                    }
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Failed to hook " + fn + " (" + mod + ") for JNI_OnLoad: " + e.message + C.RESET);
            }
        });
    });

    console.log(C.GREEN + "[+] hookArtDexLoaders installed (ART dex loaders + JNI_OnLoad watcher)" + C.RESET);
}

// ===================== MODULE: file-content (hookFileContent) =====================
// ==========================================
// FILE CONTENT READ-BACK INSPECTION
// ==========================================
//
// THE biggest gap: nothing else inspects the BYTES a file read returns. Path hooks
// (safeAttachIO) fire on open("/proc/self/status") but never see the "TracerPid: 1234"
// that comes back. This module maintains fd->path and FILE*->path maps (populated by our
// OWN detection-only open/openat/fopen return-value hooks, cleared on close/fclose) and then
// inspects the read-back / write buffers, but ONLY when the associated path is "interesting"
// (starts with /proc/ or matches TARGET_REGEX). That single gate is what keeps these
// EXTREMELY hot functions (read/pread64/write/fread/...) from flooding on normal app I/O:
// a buffer is scanned only after we have already confirmed its backing path is suspicious.
//
// Catches: TracerPid in /proc/self/status, frida/gum in /proc/self/maps, magisk in
// /proc/mounts, port 27042 in /proc/net/tcp, and DEX/ELF/ZIP magic in dropped payloads.

// fd (int) -> path string. Only "interesting" paths are ever recorded, so a present key
// already means "worth inspecting" - no re-check of the path is needed on the read side.
var FC_FD_PATHS = {};
// FILE* (pointer as string) -> path string, same "interesting only" invariant.
var FC_FILE_PATHS = {};

// Hard cap on how many entries the maps may hold. Long-running samples can churn millions
// of fds; without this the maps would grow unbounded. On overflow we drop the whole map
// (correctness is unaffected: a missing entry just means "don't inspect", never a false alert).
var FC_MAP_CAP = 4096;
var FC_FD_COUNT = 0, FC_FILE_COUNT = 0;

// Never scan more than 4096 bytes of any single buffer (per the spec) - bounds both the
// readByteArray cost and the downstream checkAndLog regex work on large reads.
var FC_SCAN_CAP = 4096;

// A path is worth tracking iff it is a /proc/ pseudo-file (TracerPid/maps/mounts/net/tcp)
// or it hits the evasion lexicon. This is the ONLY admission gate into the maps, and hence
// the only content that can ever reach the read-back inspection below.
function fcPathInteresting(path) {
    if (!path) return false;
    if (path.lastIndexOf("/proc/", 0) === 0) return true;   // startsWith("/proc/")
    return TARGET_REGEX.test(path);
}

function fcRecordFd(fd, path) {
    if (fd < 0 || !fcPathInteresting(path)) return;
    if (FC_FD_COUNT >= FC_MAP_CAP) { FC_FD_PATHS = {}; FC_FD_COUNT = 0; }
    if (FC_FD_PATHS[fd] === undefined) FC_FD_COUNT++;
    FC_FD_PATHS[fd] = path;
}

function fcRecordFile(filePtr, path) {
    if (!filePtr || filePtr.isNull() || !fcPathInteresting(path)) return;
    var key = filePtr.toString();
    if (FC_FILE_COUNT >= FC_MAP_CAP) { FC_FILE_PATHS = {}; FC_FILE_COUNT = 0; }
    if (FC_FILE_PATHS[key] === undefined) FC_FILE_COUNT++;
    FC_FILE_PATHS[key] = path;
}

function fcDropFd(fd) {
    if (FC_FD_PATHS[fd] !== undefined) { delete FC_FD_PATHS[fd]; FC_FD_COUNT--; }
}

function fcDropFile(filePtr) {
    if (!filePtr || filePtr.isNull()) return;
    var key = filePtr.toString();
    if (FC_FILE_PATHS[key] !== undefined) { delete FC_FILE_PATHS[key]; FC_FILE_COUNT--; }
}

// Scan a just-filled buffer: run the lexicon match against its printable content and, if the
// content looks like a dropped payload (DEX/CDEX/ELF/ZIP magic), hand it to dumpBuffer. Deduped
// on tag+path so a tight read loop over the same /proc file logs at most once per distinct hit.
function fcInspectBuffer(funcName, path, bufPtr, len, context) {
    if (!bufPtr || bufPtr.isNull() || len <= 0) return;
    var scan = len < FC_SCAN_CAP ? len : FC_SCAN_CAP;

    // Payload magic first: dropped DEX/ELF/ZIP rarely survives as printable UTF-8, so sniff
    // the raw bytes before the string path. Only when at least a full 4-byte magic is present.
    // dumpBuffer itself no-ops to a magic+size+preview line unless DUMP_PAYLOADS is set, so
    // this is safe to call on every interesting write/read.
    if (scan >= 4) {
        try {
            var magic = payloadMagic(bufPtr);
            if (magic) {
                var msig = "FCMAGIC|" + funcName + "|" + path + "|" + magic;
                if (!ALERT_HISTORY[msig]) {
                    markSeen(msig);
                    console.log("\n" + C.PURPLE + "[!] [FILE-CONTENT] " + magic.toUpperCase() +
                                " payload seen via " + funcName + " on " + path + C.RESET);
                    // Dump the FULL bytes-read (dumpBuffer applies its own 16 MB cap); `scan` only
                    // bounds the magic-sniff and lexicon scan, not the recovered-payload dump.
                    try { dumpBuffer("filecontent-" + funcName, bufPtr, len); } catch (e) {}
                }
            }
        } catch (e) {}
    }

    // String/lexicon match against the printable content (TracerPid:, frida, magisk, 27042, ...).
    var content = "";
    try {
        var ba = bufPtr.readByteArray(scan);
        if (ba) {
            var bytes = new Uint8Array(ba);
            var chars = [];
            for (var i = 0; i < bytes.length; i++) {
                var b = bytes[i];
                if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) chars.push(b);
            }
            for (var j = 0; j < chars.length; j += 8192) {
                content += String.fromCharCode.apply(null, chars.slice(j, j + 8192));
            }
        }
    } catch (e) { return; }
    if (!content) return;

    // Format-aware anti-analysis detection the generic lexicon cannot express:
    // - TracerPid in /proc/self/status: a NONZERO value means a debugger/Frida is attached.
    // - Frida default ports 27042/27043 in /proc/net/tcp, where the local port is UPPERCASE HEX
    //   (27042 -> 69A2, 27043 -> 69A3), so the decimal lexicon tokens can never match here.
    try {
        if (path.indexOf("/status") !== -1) {
            var tm = content.match(/TracerPid:\s*([0-9]+)/);
            if (tm && tm[1] !== "0") {
                var tsig = "TRACERPID|" + path + "|" + tm[1];
                if (!ALERT_HISTORY[tsig]) {
                    markSeen(tsig);
                    console.log("\n" + C.RED + "[!] [ANTI-DEBUG] TracerPid=" + tm[1] + " read from " +
                                path + " (a debugger/Frida is attached)" + C.RESET);
                }
            }
        }
        if (path.indexOf("/proc/net/tcp") !== -1 && /:(69A2|69A3)\b/i.test(content)) {
            var psig = "FRIDAPORT|" + path;
            if (!ALERT_HISTORY[psig]) {
                markSeen(psig);
                console.log("\n" + C.RED + "[!] [ANTI-FRIDA] Frida default port (27042/27043) scan detected in " +
                            path + C.RESET);
            }
        }
    } catch (e) {}

    var ctx = context;
    checkAndLog("FILE-CONTENT " + funcName + " (" + path + ")", content,
                function() { return getNativeBacktrace(ctx); });
}

function hookFileContent() {
    // ---- 1. fd/FILE* -> path recorders (detection-only; NO spoofing here). ----
    // These attach independently of safeAttachIO's copies: safeAttachIO does not expose the
    // retval->path mapping we need, and re-using its onLeave would entangle our map with its
    // active-bypass logic. Multiple Interceptor.attach on the same libc export is allowed.
    // We only READ retval and record; we never mutate it.

    // open/openat: path is arg[argIdx], new fd is the return value.
    [["open", 0], ["openat", 1]].forEach(function(spec) {
        var fn = spec[0], argIdx = spec[1];
        var p = getExportSafe("libc.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) { this.fcPath = readStrSafe(args[argIdx]); },
                onLeave: function (retval) {
                    if (!this.fcPath) return;
                    fcRecordFd(retval.toInt32(), this.fcPath);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // fopen: path is arg0, FILE* is the return value.
    (function() {
        var p = getExportSafe("libc.so", "fopen");
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) { this.fcPath = readStrSafe(args[0]); },
                onLeave: function (retval) {
                    if (!this.fcPath) return;
                    fcRecordFile(retval, this.fcPath);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook fopen: " + e.message + C.RESET);
        }
    })();

    // close/fclose: drop the mapping so a recycled fd/FILE* cannot alias a stale path.
    // These run unconditionally (cheap hashmap delete) - gating them would desync the maps.
    (function() {
        var pc = getExportSafe("libc.so", "close");
        if (pc) {
            try {
                Interceptor.attach(pc, {
                    onEnter: function (args) { fcDropFd(args[0].toInt32()); }
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] hookFileContent: failed to hook close: " + e.message + C.RESET);
            }
        }
        var pf = getExportSafe("libc.so", "fclose");
        if (pf) {
            try {
                Interceptor.attach(pf, {
                    onEnter: function (args) { fcDropFile(args[0]); }
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] hookFileContent: failed to hook fclose: " + e.message + C.RESET);
            }
        }
    })();

    // ---- 2. Raw read-back: read / pread64 / pread. GATE = fd present in FC_FD_PATHS. ----
    // read/pread are EXTREMELY hot. We do the map lookup in onEnter and set this.fcSkip so the
    // vast majority of calls (fd not interesting) bail immediately without capturing anything.
    // read(fd,buf,n) and pread64(fd,buf,n,off) share fd=arg0, buf=arg1, retval=bytes read.
    ["read", "pread64", "pread"].forEach(function(fn) {
        var p = getExportSafe("libc.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    // Content gate: only fds whose backing path we recorded as /proc/ or a
                    // target path are ever inspected - normal file reads are skipped outright.
                    var path = FC_FD_PATHS[args[0].toInt32()];
                    if (path === undefined || !isTargetCaller(this.returnAddress)) {
                        this.fcSkip = true;
                        return;
                    }
                    this.fcSkip = false;
                    this.fcPath = path;
                    this.fcBuf = args[1];
                    this.fcCtx = this.context;
                },
                onLeave: function (retval) {
                    if (this.fcSkip) return;
                    var n = retval.toInt32();
                    if (n <= 0) return;
                    fcInspectBuffer(fn, this.fcPath, this.fcBuf, n, this.fcCtx);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- 3. stdio read-back: fread / fgets. GATE = FILE* present in FC_FILE_PATHS. ----
    // fread(ptr, size, nmemb, FILE*): buffer arg0, FILE* arg3, retval = items read.
    (function() {
        var p = getExportSafe("libc.so", "fread");
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var path = FC_FILE_PATHS[args[3].toString()];
                    if (path === undefined || !isTargetCaller(this.returnAddress)) {
                        this.fcSkip = true;
                        return;
                    }
                    this.fcSkip = false;
                    this.fcPath = path;
                    this.fcBuf = args[0];
                    this.fcSize = args[1].toInt32();
                    this.fcCtx = this.context;
                },
                onLeave: function (retval) {
                    if (this.fcSkip) return;
                    var items = retval.toInt32();
                    if (items <= 0 || this.fcSize <= 0) return;
                    var bytes = items * this.fcSize;
                    if (bytes <= 0) return;
                    if (bytes > FC_SCAN_CAP) bytes = FC_SCAN_CAP;
                    fcInspectBuffer("fread", this.fcPath, this.fcBuf, bytes, this.fcCtx);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook fread: " + e.message + C.RESET);
        }
    })();

    // fgets(buf, size, FILE*): line buffer arg0, FILE* arg2, retval = buf (or NULL at EOF).
    (function() {
        var p = getExportSafe("libc.so", "fgets");
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var path = FC_FILE_PATHS[args[2].toString()];
                    if (path === undefined || !isTargetCaller(this.returnAddress)) {
                        this.fcSkip = true;
                        return;
                    }
                    this.fcSkip = false;
                    this.fcPath = path;
                    this.fcBuf = args[0];
                    this.fcCtx = this.context;
                },
                onLeave: function (retval) {
                    if (this.fcSkip || retval.isNull()) return;
                    // NUL-terminated line; readStrSafe bounds it, then scan the string directly.
                    var line = readStrSafe(this.fcBuf, FC_SCAN_CAP);
                    if (!line) return;
                    var ctx = this.fcCtx, path = this.fcPath;
                    checkAndLog("FILE-CONTENT fgets (" + path + ")", line,
                                function() { return getNativeBacktrace(ctx); });
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook fgets: " + e.message + C.RESET);
        }
    })();

    // ---- 4. getline / getdelim. GATE = FILE* present in FC_FILE_PATHS. ----
    // getline(char **lineptr, size_t *n, FILE*): the malware-favourite for scanning /proc line
    // by line. The line lives at *lineptr (arg0 is char**), the FILE* is arg2, retval = length.
    ["getline", "getdelim"].forEach(function(fn) {
        var p = getExportSafe("libc.so", fn);
        if (!p) return;
        // getdelim adds an int delim arg (arg2), pushing FILE* from arg2 to arg3.
        var fileIdx = (fn === "getdelim") ? 3 : 2;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var path = FC_FILE_PATHS[args[fileIdx].toString()];
                    if (path === undefined || !isTargetCaller(this.returnAddress)) {
                        this.fcSkip = true;
                        return;
                    }
                    this.fcSkip = false;
                    this.fcPath = path;
                    this.fcLinePtrPtr = args[0]; // char** - the line buffer is written by the callee
                    this.fcCtx = this.context;
                },
                onLeave: function (retval) {
                    if (this.fcSkip) return;
                    var n = retval.toInt32();
                    if (n <= 0) return;
                    var linePtr;
                    try { linePtr = this.fcLinePtrPtr.readPointer(); } catch (e) { return; }
                    if (!linePtr || linePtr.isNull()) return;
                    fcInspectBuffer(fn, this.fcPath, linePtr, n, this.fcCtx);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- 5. Writes: write / pwrite64 / pwrite. Inspect DROPPED content. ----
    // GATE: only inspect when the destination fd's path is interesting (in FC_FD_PATHS).
    // Buffer content is the SOURCE (valid at onEnter), so we gate on the fd map before touching
    // anything - normal writes to normal files are skipped with no buffer read.
    // write(fd,buf,n) and pwrite64(fd,buf,n,off) share fd=arg0, buf=arg1, len=arg2.
    ["write", "pwrite64", "pwrite"].forEach(function(fn) {
        var p = getExportSafe("libc.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var path = FC_FD_PATHS[args[0].toInt32()];
                    if (path === undefined || !isTargetCaller(this.returnAddress)) return;
                    var len = args[2].toInt32();
                    if (len <= 0) return;
                    fcInspectBuffer(fn, path, args[1], len, this.context);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // fwrite(ptr, size, nmemb, FILE*): buffer arg0, FILE* arg3.
    (function() {
        var p = getExportSafe("libc.so", "fwrite");
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var path = FC_FILE_PATHS[args[3].toString()];
                    if (path === undefined || !isTargetCaller(this.returnAddress)) return;
                    var size = args[1].toInt32();
                    var nmemb = args[2].toInt32();
                    if (size <= 0 || nmemb <= 0) return;
                    var bytes = size * nmemb;
                    if (bytes <= 0) return;
                    if (bytes > FC_SCAN_CAP) bytes = FC_SCAN_CAP;
                    fcInspectBuffer("fwrite", path, args[0], bytes, this.context);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] hookFileContent: failed to hook fwrite: " + e.message + C.RESET);
        }
    })();

    console.log(C.GREEN + "[+] Hooked file-content read-back (read/pread64/fread/fgets/getline/getdelim) " +
                "and writes (write/pwrite64/fwrite), gated on fd/FILE*->path map." + C.RESET);
}

// ===================== MODULE: fs-recon (hookFsRecon) =====================
// ==========================================
// FILESYSTEM RECON & MOUNT/ROOT DETECTION (detection-only, no spoof)
// ==========================================
//
// Covers directory enumeration, mount-table parsing, filesystem-stat, and
// mount/rename/unlink syscalls that the existing path-EXISTENCE hooks
// (open/stat/access family) do NOT touch. Everything here is DETECTION ONLY -
// it never mutates the sample's behavior.
//
// GATING (per the flood rules):
//   - Every hook is gated on isTargetCaller(this.returnAddress) first.
//   - opendir/statfs/mount/rename/unlink families are LOW frequency (per open
//     dir / per fs op), so plain detection on the path arg is enough and
//     self-dedupes via ALERT_HISTORY.
//   - readdir/readdir64 are the ONLY hot funcs here. To avoid flooding we NEVER
//     log per call: gated on isTargetCaller, we read the single d_name C-string
//     at the bionic offset and hand it to checkAndLog, which no-ops unless it
//     matches the lexicon (frida-server/su/magisk/...) and then dedupes. We scan
//     every entry name (directory contents are exactly where the artifact name
//     shows up) but log at most once per unique name.

// bionic `struct dirent` layout is identical on 32- and 64-bit Android:
//   uint64_t d_ino (@0, 8) + int64_t d_off (@8, 8) + uint16_t d_reclen (@16, 2)
//   + uint8_t d_type (@18, 1) => char d_name[] @ 19 (char[] needs no padding).
var _DIRENT_DNAME_OFF = 19;

// `struct mntent` (bionic/glibc): char *mnt_fsname (device) at offset 0, then
// char *mnt_dir (mount point) at offset pointerSize.
function _readMntent(mntPtr, source, context) {
    try {
        if (mntPtr == null || mntPtr.isNull()) return;
        var fsname = readStrSafe(mntPtr.readPointer());                       // mnt_fsname
        var dir = readStrSafe(mntPtr.add(Process.pointerSize).readPointer()); // mnt_dir
        var combined = fsname + " " + dir;
        checkAndLog(source, combined, function() { return getNativeBacktrace(context); });
    } catch (e) {}
}

// Two-path detection-only attach (mount/rename/renameat2): scan BOTH paths.
// argA/argB are the arg indices holding the two C-string paths. Single-path
// cases are handled by the shared safeAttachDetect(mod, func, argIndex) helper.
function _attachTwoPathDetect(moduleName, funcName, argA, argB) {
    var p = getExportSafe(moduleName, funcName);
    if (!p) return false;
    try {
        Interceptor.attach(p, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) return;
                var a = readStrSafe(args[argA]);
                var b = readStrSafe(args[argB]);
                var ctx = this.context;
                if (a) checkAndLog(funcName + " (from)", a, function() { return getNativeBacktrace(ctx); });
                if (b) checkAndLog(funcName + " (to)", b, function() { return getNativeBacktrace(ctx); });
            }
        });
        console.log(C.GREEN + "[+] Hooked (fs-recon): " + funcName + C.RESET);
        return true;
    } catch (e) {
        console.log(C.RED + "[-] Failed to hook " + funcName + ": " + e.message + C.RESET);
        return false;
    }
}

function hookFsRecon() {
    // ----- Directory enumeration: opendir (path arg0) -----
    // Low frequency (once per directory opened) so plain detection on arg0 is fine.
    safeAttachDetect("libc.so", "opendir", 0);

    // ----- readdir / readdir64: read returned `struct dirent*` d_name -----
    // HOT path. Gated on isTargetCaller; we read one NUL-terminated C-string per
    // call and feed it to checkAndLog (no unconditional logging), so non-matching
    // entries are silent and matching names (frida-server/su/magisk/...) log at
    // most once each via ALERT_HISTORY dedup. On 64-bit bionic readdir IS
    // readdir64 (same symbol); the duplicate listener self-dedupes via checkAndLog.
    ["readdir", "readdir64"].forEach(function(funcName) {
        var p = getExportSafe("libc.so", funcName);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function () {
                    // Cheap module gate BEFORE any work; flag carried to onLeave.
                    this.skip = !isTargetCaller(this.returnAddress);
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip || retval == null || retval.isNull()) return;
                    // readStrSafe is already null/fault-safe; retval+offset is a valid read.
                    var name = readStrSafe(retval.add(_DIRENT_DNAME_OFF));
                    // Skip "." / ".." and empty names - zero signal, avoids churn.
                    if (!name || name === "." || name === "..") return;
                    var ctx = this.ctx;
                    checkAndLog(funcName + " d_name", name, function() { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked (fs-recon): " + funcName + " (d_name @ " + _DIRENT_DNAME_OFF + ")" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook " + funcName + ": " + e.message + C.RESET);
        }
    });

    // ----- Mount-table parsing: getmntent / getmntent_r return `struct mntent*` -----
    // Classic root/Magisk detection walks /proc/mounts via setmntent+getmntent
    // looking for suspicious mnt_fsname/mnt_dir (e.g. magisk, /data/adb). Both
    // funcs return the populated `struct mntent*` (getmntent_r returns its arg1
    // mntent* on success, NULL at EOF). Read both fields on leave.
    ["getmntent", "getmntent_r"].forEach(function(funcName) {
        var p = getExportSafe("libc.so", funcName);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function () {
                    this.skip = !isTargetCaller(this.returnAddress);
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip || retval == null || retval.isNull()) return;
                    _readMntent(retval, funcName, this.ctx);
                }
            });
            console.log(C.GREEN + "[+] Hooked (fs-recon): " + funcName + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook " + funcName + ": " + e.message + C.RESET);
        }
    });

    // hasmntopt(const struct mntent *mnt, const char *opt): scan the mntent it
    // inspects (arg0) plus the option string (arg1). Self-skips via getExportSafe
    // when the target does not export hasmntopt.
    (function() {
        var p = getExportSafe("libc.so", "hasmntopt");
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var ctx = this.context;
                    _readMntent(args[0], "hasmntopt (mnt)", ctx);
                    var opt = readStrSafe(args[1]);
                    if (opt) checkAndLog("hasmntopt (opt)", opt, function() { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked (fs-recon): hasmntopt" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook hasmntopt: " + e.message + C.RESET);
        }
    })();

    // ----- Filesystem stat: statfs / statfs64 / statvfs / statvfs64 (path arg0) -----
    // Used to fingerprint filesystem type/flags of suspicious mount points. Low frequency.
    safeAttachDetect("libc.so", "statfs", 0);
    safeAttachDetect("libc.so", "statfs64", 0);
    safeAttachDetect("libc.so", "statvfs", 0);
    safeAttachDetect("libc.so", "statvfs64", 0);

    // ----- mount(source, target, ...) / umount2(target,flags) / umount(target) -----
    // mount: scan both source device (arg0) and target mountpoint (arg1).
    // umount2/umount: single target path at arg0.
    _attachTwoPathDetect("libc.so", "mount", 0, 1);
    safeAttachDetect("libc.so", "umount2", 0);
    safeAttachDetect("libc.so", "umount", 0);

    // ----- rename(old,new) / renameat2/renameat: hiding/moving artifacts -----
    // rename paths are args 0 and 1; renameat2/renameat paths are args 1 and 3
    // (dirfds occupy args 0 and 2).
    _attachTwoPathDetect("libc.so", "rename", 0, 1);
    _attachTwoPathDetect("libc.so", "renameat2", 1, 3);
    _attachTwoPathDetect("libc.so", "renameat", 1, 3);

    // ----- unlink(path) / unlinkat(dirfd,path,flags) / remove(path) -----
    safeAttachDetect("libc.so", "unlink", 0);
    safeAttachDetect("libc.so", "unlinkat", 1);
    safeAttachDetect("libc.so", "remove", 0);

    console.log(C.GREEN + "[+] Filesystem recon hooks installed (opendir/readdir/getmntent/statfs/mount/rename/unlink)" + C.RESET);
}

// ===================== MODULE: crypto-java (hookCryptoJava) =====================
// ==========================================
// JAVA JCA CRYPTO HOOKS (KEY / IV / PLAINTEXT RECOVERY)
// ==========================================

// Local helper: convert a Java byte[] (signed bytes) to a lowercase hex string, bounded to
// maxLen bytes so a multi-MB decrypted blob cannot flood the console. Appends a truncation
// marker with the true length when clipped. Returns "" for null/empty input.
// Truncate drastically: print only first 8 and last 8 bytes of a buffer
function jbytesToHex(jbytes, maxLen) {
    if (jbytes === null || jbytes === undefined) return "";
    var len = 0;
    try { len = jbytes.length; } catch (e) { return ""; }
    if (typeof len !== "number" || len === 0) return "";
    
    var cap = (maxLen && maxLen < len) ? maxLen : len;
    var hex = "";
    
    // If truncation is disabled or the buffer is small, print the requested cap
    if (!TRUNCATE_HEX || cap <= 24) {
        for (var i = 0; i < cap; i++) {
            var b = jbytes[i] & 0xff;
            hex += (b < 16 ? "0" : "") + b.toString(16);
        }
        if (cap < len) hex += "... [" + len + " bytes total]";
    } else {
        // Truncate drastically: First 8 bytes
        for (var i = 0; i < 8; i++) {
            var b = jbytes[i] & 0xff;
            hex += (b < 16 ? "0" : "") + b.toString(16);
        }
        hex += "...";
        // Last 8 bytes
        for (var i = cap - 8; i < cap; i++) {
            var b = jbytes[i] & 0xff;
            hex += (b < 16 ? "0" : "") + b.toString(16);
        }
        hex += " (" + len + " bytes)";
    }
    return hex;
}

// Local helper: decode a Java byte[] to a printable ASCII string for checkAndLog, so a decrypted
// plaintext containing a target token (e.g. "frida", "magisk", a C2 URL) is matched by the shared
// lexicon. Non-printable bytes are dropped; bounded to maxLen bytes. Returns "" when the buffer is
// mostly binary (fewer than ~40% printable) to avoid noise.
function jbytesToPrintable(jbytes, maxLen) {
    if (jbytes === null || jbytes === undefined) return "";
    var len = 0;
    try { len = jbytes.length; } catch (e) { return ""; }
    if (typeof len !== "number" || len === 0) return "";
    var cap = (maxLen && maxLen < len) ? maxLen : len;
    var out = "";
    var printable = 0;
    for (var i = 0; i < cap; i++) {
        var b = jbytes[i] & 0xff;
        if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
            out += String.fromCharCode(b);
            printable++;
        }
    }
    if (cap > 0 && (printable / cap) < 0.4) return "";
    return out;
}

// Local helper: copy up to maxLen bytes of a Java byte[] into a native buffer so the shared
// dumpBuffer/payloadMagic helpers (which take a NativePointer) can magic-sniff and optionally dump
// a decrypted second-stage payload. NativePointer.writeByteArray does NOT accept a Java array
// wrapper, so we first build a plain JS array of unsigned bytes. Returns { ptr, len } or null.
function jbytesToNative(jbytes, maxLen) {
    try {
        if (jbytes === null || jbytes === undefined) return null;
        var len = jbytes.length;
        if (typeof len !== "number" || len <= 0) return null;
        var cap = (maxLen && maxLen < len) ? maxLen : len;
        var arr = new Array(cap);
        for (var i = 0; i < cap; i++) arr[i] = jbytes[i] & 0xff;
        var p = Memory.alloc(cap);
        p.writeByteArray(arr);
        return { ptr: p, len: cap };
    } catch (e) { return null; }
}

// Local helper: copy a bounded [off, off+n) slice of a Java byte[] into a plain JS array of signed
// bytes that jbytesToHex / jbytesToPrintable can consume (they only read [i] and .length).
function jbytesSlice(jbytes, off, n, maxLen) {
    var slice = [];
    try {
        if (jbytes === null || jbytes === undefined) return slice;
        var total = jbytes.length;
        if (typeof total !== "number") return slice;
        var lim = (maxLen && maxLen < n) ? maxLen : n;
        for (var i = 0; i < lim; i++) {
            var idx = off + i;
            if (idx < 0 || idx >= total) break;
            slice.push(jbytes[idx]);
        }
    } catch (e) {}
    return slice;
}

function hookCryptoJava() {
    if (!Java.available) {
        console.log(C.YELLOW + "[!] Java is not available. Skipping JCA crypto hooks." + C.RESET);
        return;
    }

    Java.perform(function () {
        // Gating note: these are Java-layer JCA hooks, NOT hot native functions, so isTargetCaller /
        // PROT_EXEC-style native gating does not apply. Output volume is bounded four ways instead:
        // hex previews are capped (jbytesToHex maxLen), decoded plaintext is run through the shared
        // checkAndLog lexicon (only target-string hits print), raw key/IV/nonce capture is deduped
        // via markSeen/ALERT_HISTORY, and the payload-dump path (native copy + [DUMP] line) only runs
        // when the output carries a recognizable dex/elf/zip magic OR DUMP_PAYLOADS is on - so a tight
        // per-message crypto loop over benign ciphertext does not emit a line per doFinal.

        var HEX_CAP = 512;      // max bytes rendered as hex for payloads
        var PLAIN_CAP = 4096;   // max bytes decoded for lexicon matching
        var DUMP_CAP = 4 * 1024 * 1024; // max bytes copied to native for magic-sniff / dump

        // Sniff a decrypted output byte[] for a dex/elf/zip payload and, only then (or when
        // DUMP_PAYLOADS is on), hand a native copy to the shared dumpBuffer. Bounded copy.
        function sniffAndMaybeDump(tag, jbytes, outLen) {
            try {
                if (outLen <= 0) return;
                var native = jbytesToNative(jbytes, DUMP_CAP);
                if (!native) return;
                // Only emit / dump when it looks like a real payload, unless dumping is forced on.
                if (DUMP_PAYLOADS || payloadMagic(native.ptr) !== null) {
                    // dumpBuffer dedups on the buffer POINTER, but jbytesToNative allocates a fresh
                    // pointer every call, so identical decrypted payloads would re-dump on every
                    // doFinal. Dedup on stable content (tag|len|leading bytes) first.
                    var csig = "cryptodump|" + tag + "|" + native.len + "|" + hexPreview(native.ptr, 16);
                    if (!ALERT_HISTORY[csig]) {
                        markSeen(csig);
                        dumpBuffer(tag, native.ptr, native.len);
                    }
                }
            } catch (e) {}
        }

        // ---- javax.crypto.Cipher (doFinal + init) ----
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var CIPHER_STATE_MAP = {}; // Map to track Key & IV per cipher instance

            // Cipher.init: opmode + key + optional params. 
            // We capture the Key and IV here to print them later during doFinal.
            try {
                var opName = function (op) {
                    // Cipher.ENCRYPT_MODE=1, DECRYPT_MODE=2, WRAP=3, UNWRAP=4
                    return op === 1 ? "ENCRYPT" : op === 2 ? "DECRYPT" :
                           op === 3 ? "WRAP" : op === 4 ? "UNWRAP" : ("MODE_" + op);
                };
                Cipher.init.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try {
                            var op = arguments.length > 0 ? arguments[0] : -1;
                            var algo = "";
                            try { algo = this.getAlgorithm(); } catch (e) {}
                            var sig = "cipher.init|" + algo + "|" + op;
                            if (!ALERT_HISTORY[sig]) {
                                markSeen(sig);
                                console.log("\n" + C.PURPLE + "[!] [CRYPTO] Cipher.init(" + opName(op) +
                                    ") algorithm=" + algo + C.RESET);
                            }
                        } catch (e) {}
                        
                        var ret = ov.apply(this, arguments);

                        // Capture Key and IV state after init succeeds
                        try {
                            var hash = this.hashCode();
                            var keyHex = "[Unknown/Unexportable]";
                            var ivHex = "[None]";
                            
                            // Extract Key
                            if (arguments.length > 1 && arguments[1] !== null) {
                                var keyObj = Java.cast(arguments[1], Java.use("java.security.Key"));
                                var encoded = keyObj.getEncoded();
                                if (encoded) keyHex = jbytesToHex(encoded, HEX_CAP);
                            }
                            
                            // Extract IV
                            var ivBytes = this.getIV();
                            if (ivBytes) ivHex = jbytesToHex(ivBytes, HEX_CAP);
                            
                            CIPHER_STATE_MAP[hash] = { key: keyHex, iv: ivHex };
                        } catch (e) {}

                        return ret;
                    };
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook Cipher.init: " + e.message + C.RESET);
            }

            // Cipher.doFinal (all overloads): Extract the input payload and retrieve the saved Key/IV state.
            try {
                Cipher.doFinal.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        // Describe the first byte[] argument (input ciphertext/plaintext).
                        var inLen = -1;
                        var inHex = "[Empty]";
                        try {
                            for (var a = 0; a < arguments.length; a++) {
                                var arg = arguments[a];
                                if (arg !== null && arg !== undefined && typeof arg === "object" &&
                                    typeof arg.length === "number") {
                                    inLen = arg.length;
                                    inHex = jbytesToHex(arg, HEX_CAP);
                                    break;
                                }
                            }
                        } catch (e) {}

                        var out = ov.apply(this, arguments);

                        try {
                            var algo = "";
                            try { algo = this.getAlgorithm(); } catch (e) {}
                            
                            // Retrieve saved state (Key/IV) for this exact cipher
                            var state = { key: "[Unknown]", iv: "[Unknown]" };
                            try {
                                var hash = this.hashCode();
                                if (CIPHER_STATE_MAP[hash]) state = CIPHER_STATE_MAP[hash];
                            } catch (e) {}

                            var isBytes = (out !== null && out !== undefined &&
                                           typeof out === "object" && typeof out.length === "number");
                            var outLen = isBytes ? out.length : -1;

                            console.log("\n" + C.CYAN + "[!] [CRYPTO] Cipher.doFinal algorithm=" + algo +
                                " in=" + (inLen >= 0 ? inLen : "?") + "B out=" +
                                (outLen >= 0 ? outLen : "?") + "B" + C.RESET);

                            if (isBytes && outLen > 0) {
                                var plain = jbytesToPrintable(out, PLAIN_CAP);
                                var hex = jbytesToHex(out, HEX_CAP);
                                
                                if (plain) {
                                    // Print the full context before the green plaintext
                                    console.log(C.YELLOW + "    -> [Decryption Parameters]" + C.RESET);
                                    console.log(C.YELLOW + "       Algorithm : " + algo + C.RESET);
                                    console.log(C.YELLOW + "       Key (Hex) : " + state.key + C.RESET);
                                    console.log(C.YELLOW + "       IV  (Hex) : " + state.iv + C.RESET);
                                    console.log(C.YELLOW + "       Input/Enc : " + inHex + C.RESET);
                                    console.log(C.GREEN  + "    -> Plaintext : " + plain + C.RESET);
                                } else {
                                    // Fallback for binary payloads
                                    console.log(C.YELLOW + "    -> Output hex: " + hex + C.RESET);
                                }
                                
                                if (plain) checkAndLog("Cipher.doFinal output", plain, null);
                                sniffAndMaybeDump("cipher_doFinal_" +
                                    String(algo).replace(/[^A-Za-z0-9]/g, "_"), out, outLen);
                            }
                        } catch (e) {}
                        return out;
                    };
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook Cipher.doFinal: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use javax.crypto.Cipher: " + e.message + C.RESET);
        }

        // ---- javax.crypto.spec.SecretKeySpec: CAPTURE raw key bytes ----
        // Where the actual symmetric key material is constructed. Capture byte[] key + algorithm.
        try {
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            SecretKeySpec.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        // Overloads: (byte[] key, String algo) or (byte[] key, int off, int len, String algo).
                        // For the offset/length form, hex ONLY the real [off, off+len) key slice.
                        var algo = arguments.length > 0 ? arguments[arguments.length - 1] : "";
                        var keySrc = (arguments.length === 4)
                            ? jbytesSlice(arguments[0], arguments[1], arguments[2], HEX_CAP)
                            : (arguments.length > 0 ? arguments[0] : null);
                        var hex = jbytesToHex(keySrc, HEX_CAP);
                        var sig = "seckey|" + algo + "|" + hex;
                        if (!ALERT_HISTORY[sig]) {
                            markSeen(sig);
                            console.log("\n" + C.RED + "[!] [CRYPTO KEY] SecretKeySpec algorithm=" +
                                algo + C.RESET);
                            console.log(C.YELLOW + "    -> Key hex: " + hex + C.RESET);
                        }
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use SecretKeySpec: " + e.message + C.RESET);
        }

        // ---- javax.crypto.spec.IvParameterSpec: CAPTURE IV/nonce ----
        try {
            var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            IvParameterSpec.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        // (byte[] iv) or (byte[] iv, int off, int len) - slice for the offset form.
                        var ivSrc = (arguments.length === 3)
                            ? jbytesSlice(arguments[0], arguments[1], arguments[2], HEX_CAP)
                            : (arguments.length > 0 ? arguments[0] : null);
                        var hex = jbytesToHex(ivSrc, HEX_CAP);
                        var sig = "iv|" + hex;
                        if (!ALERT_HISTORY[sig]) {
                            markSeen(sig);
                            console.log("\n" + C.PURPLE + "[!] [CRYPTO IV] IvParameterSpec" + C.RESET);
                            console.log(C.YELLOW + "    -> IV hex: " + hex + C.RESET);
                        }
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use IvParameterSpec: " + e.message + C.RESET);
        }

        // ---- javax.crypto.spec.GCMParameterSpec: CAPTURE AEAD nonce ----
        try {
            var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
            GCMParameterSpec.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        // (int tLen, byte[] src) or (int tLen, byte[] src, int off, int len)
                        var tLen = arguments.length > 0 ? arguments[0] : -1;
                        var nonceSrc = (arguments.length === 4)
                            ? jbytesSlice(arguments[1], arguments[2], arguments[3], HEX_CAP)
                            : (arguments.length > 1 ? arguments[1] : null);
                        var hex = jbytesToHex(nonceSrc, HEX_CAP);
                        var sig = "gcm|" + tLen + "|" + hex;
                        if (!ALERT_HISTORY[sig]) {
                            markSeen(sig);
                            console.log("\n" + C.PURPLE + "[!] [CRYPTO IV] GCMParameterSpec tagLenBits=" +
                                tLen + C.RESET);
                            console.log(C.YELLOW + "    -> Nonce hex: " + hex + C.RESET);
                        }
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use GCMParameterSpec: " + e.message + C.RESET);
        }

        // ---- java.util.Base64$Decoder.decode: input + output (API 26+) ----
        try {
            var B64Decoder = Java.use("java.util.Base64$Decoder");
            B64Decoder.decode.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var out = ov.apply(this, arguments);
                    try {
                        var inArg = arguments.length > 0 ? arguments[0] : null;
                        var inDesc = "";
                        if (typeof inArg === "string") {
                            inDesc = inArg.length + " chars";
                            checkAndLog("Base64.Decoder input", inArg, null);
                        } else if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                                   typeof inArg.length === "number") {
                            inDesc = inArg.length + "B";
                        }
                        var isBytes = (out !== null && out !== undefined &&
                                       typeof out === "object" && typeof out.length === "number");
                        if (isBytes) {
                            console.log("\n" + C.CYAN + "[!] [CRYPTO] Base64.Decoder.decode in=" +
                                inDesc + " out=" + out.length + "B" + C.RESET);
                            console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(out, HEX_CAP) + C.RESET);
                            var plain = jbytesToPrintable(out, PLAIN_CAP);
                            if (plain) checkAndLog("Base64.Decoder output", plain, null);
                        }
                    } catch (e) {}
                    return out;
                };
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use java.util.Base64$Decoder: " + e.message + C.RESET);
        }

        // ---- android.util.Base64.decode (static): input + output ----
        try {
            var AndroidB64 = Java.use("android.util.Base64");
            AndroidB64.decode.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var out = ov.apply(this, arguments);
                    try {
                        var inArg = arguments.length > 0 ? arguments[0] : null;
                        var inDesc = "";
                        if (typeof inArg === "string") {
                            inDesc = inArg.length + " chars";
                            checkAndLog("android.util.Base64 input", inArg, null);
                        } else if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                                   typeof inArg.length === "number") {
                            inDesc = inArg.length + "B";
                        }
                        var isBytes = (out !== null && out !== undefined &&
                                       typeof out === "object" && typeof out.length === "number");
                        if (isBytes) {
                            console.log("\n" + C.CYAN + "[!] [CRYPTO] android.util.Base64.decode in=" +
                                inDesc + " out=" + out.length + "B" + C.RESET);
                            console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(out, HEX_CAP) + C.RESET);
                            var plain = jbytesToPrintable(out, PLAIN_CAP);
                            if (plain) checkAndLog("android.util.Base64 output", plain, null);
                        }
                    } catch (e) {}
                    return out;
                };
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use android.util.Base64: " + e.message + C.RESET);
        }

        // ---- java.util.zip.Inflater.inflate: decompressed output ----
        // inflate(byte[] out [,int off,int len]) returns bytes written INTO the supplied output
        // buffer. Read back the written slice to recover the decompressed (deflate-packed) payload.
        // The inflate(ByteBuffer) overload has no .length arg and is skipped by the isBytes guard.
        try {
            var Inflater = Java.use("java.util.zip.Inflater");
            Inflater.inflate.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var n = ov.apply(this, arguments);
                    try {
                        var buf = arguments.length > 0 ? arguments[0] : null;
                        var off = (arguments.length > 2 && typeof arguments[1] === "number") ? arguments[1] : 0;
                        var isBytes = (buf !== null && buf !== undefined &&
                                       typeof buf === "object" && typeof buf.length === "number");
                        var written = (typeof n === "number") ? n : 0;
                        if (isBytes && written > 0) {
                            var slice = jbytesSlice(buf, off, written, PLAIN_CAP);
                            if (slice.length > 0) {
                                // Mute the console flood
                                // console.log("\n" + C.CYAN + "[!] [CRYPTO] Inflater.inflate decompressed=" +
                                //    written + "B" + C.RESET);
                                // console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(slice, HEX_CAP) + C.RESET);
                                
                                var plain = jbytesToPrintable(slice, PLAIN_CAP);
                                if (plain) checkAndLog("Inflater.inflate output", plain, null); // Still scans for threats!
                            }
                        }
                    } catch (e) {}
                    return n;
                };
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use java.util.zip.Inflater: " + e.message + C.RESET);
        }

        // ---- java.util.zip.GZIPInputStream.read: decompressed output ----
        // read(byte[] b, int off, int len) returns bytes decompressed into b. Read back the slice.
        // Capture the original overload; calling this.read(...) inside .implementation would recurse.
        try {
            var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
            var gzipReadOv = GZIPInputStream.read.overload("[B", "int", "int");
            gzipReadOv.implementation = function (b, off, len) {
                var n = gzipReadOv.call(this, b, off, len);
                try {
                    var isBytes = (b !== null && b !== undefined &&
                                   typeof b === "object" && typeof b.length === "number");
                    if (typeof n === "number" && n > 0 && isBytes) {
                        var slice = jbytesSlice(b, off, n, PLAIN_CAP);
                        if (slice.length > 0) {
                            console.log("\n" + C.CYAN + "[!] [CRYPTO] GZIPInputStream.read decompressed=" +
                                n + "B" + C.RESET);
                            console.log(C.YELLOW + "    -> Output hex: " + jbytesToHex(slice, HEX_CAP) + C.RESET);
                            var plain = jbytesToPrintable(slice, PLAIN_CAP);
                            if (plain) checkAndLog("GZIPInputStream.read output", plain, null);
                        }
                    }
                } catch (e) {}
                return n;
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook GZIPInputStream.read: " + e.message + C.RESET);
        }

        // ---- javax.crypto.Mac.init + doFinal: HMAC key + message ----
        try {
            var Mac = Java.use("javax.crypto.Mac");
            try {
                Mac.init.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try {
                            var algo = "";
                            try { algo = this.getAlgorithm(); } catch (e) {}
                            // arg0 is a Key; a SecretKeySpec's raw bytes are captured on construction.
                            var sig = "mac.init|" + algo;
                            if (!ALERT_HISTORY[sig]) {
                                markSeen(sig);
                                console.log("\n" + C.PURPLE + "[!] [CRYPTO] Mac.init algorithm=" +
                                    algo + C.RESET);
                            }
                        } catch (e) {}
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook Mac.init: " + e.message + C.RESET);
            }
            try {
                Mac.doFinal.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var inArg = arguments.length > 0 ? arguments[0] : null;
                        var inLen = (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                                     typeof inArg.length === "number") ? inArg.length : -1;
                        var out = ov.apply(this, arguments);
                        try {
                            var algo = "";
                            try { algo = this.getAlgorithm(); } catch (e) {}
                            var isBytes = (out !== null && out !== undefined &&
                                           typeof out === "object" && typeof out.length === "number");
                            console.log("\n" + C.CYAN + "[!] [CRYPTO] Mac.doFinal(" + algo + ") msg=" +
                                (inLen >= 0 ? inLen + "B" : "?") + " mac=" +
                                (isBytes ? out.length + "B" : "?") + C.RESET);
                            if (inLen > 0) {
                                var msgPlain = jbytesToPrintable(inArg, PLAIN_CAP);
                                if (msgPlain) checkAndLog("Mac.doFinal message", msgPlain, null);
                            }
                            if (isBytes && out.length > 0) {
                                console.log(C.YELLOW + "    -> MAC hex: " + jbytesToHex(out, HEX_CAP) + C.RESET);
                            }
                        } catch (e) {}
                        return out;
                    };
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook Mac.doFinal: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use javax.crypto.Mac: " + e.message + C.RESET);
        }

        // ---- java.security.MessageDigest.update + digest: hashed input ----
        try {
            var MessageDigest = Java.use("java.security.MessageDigest");
            try {
                MessageDigest.update.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try {
                            var inArg = arguments.length > 0 ? arguments[0] : null;
                            if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                                typeof inArg.length === "number" && inArg.length > 0) {
                                var plain = jbytesToPrintable(inArg, PLAIN_CAP);
                                if (plain) checkAndLog("MessageDigest.update input", plain, null);
                            }
                        } catch (e) {}
                        return ov.apply(this, arguments);
                    };
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook MessageDigest.update: " + e.message + C.RESET);
            }
            try {
                MessageDigest.digest.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        // Only the single-arg digest(byte[] input) overload feeds data via arg0.
                        // In digest(byte[] buf, int offset, int len) arg0 is the OUTPUT buffer, so
                        // scanning it as input would misreport stale/output bytes - gate on arity 1.
                        try {
                            var inArg = arguments.length === 1 ? arguments[0] : null;
                            if (inArg !== null && inArg !== undefined && typeof inArg === "object" &&
                                typeof inArg.length === "number" && inArg.length > 0) {
                                var plain = jbytesToPrintable(inArg, PLAIN_CAP);
                                if (plain) checkAndLog("MessageDigest.digest input", plain, null);
                            }
                        } catch (e) {}
                        var out = ov.apply(this, arguments);
                        try {
                            var algo = "";
                            try { algo = this.getAlgorithm(); } catch (e) {}
                            var isBytes = (out !== null && out !== undefined &&
                                           typeof out === "object" && typeof out.length === "number");
                            if (isBytes && out.length > 0) {
                                console.log("\n" + C.CYAN + "[!] [CRYPTO] MessageDigest.digest(" + algo +
                                    ") -> " + jbytesToHex(out, HEX_CAP) + C.RESET);
                            }
                        } catch (e) {}
                        return out;
                    };
                });
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook MessageDigest.digest: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use java.security.MessageDigest: " + e.message + C.RESET);
        }

        console.log(C.GREEN + "[+] Hooked Java JCA crypto (Cipher, SecretKeySpec, Iv/GCM, Base64, Inflater/GZIP, Mac, MessageDigest)" + C.RESET);
    });
}

// ===================== MODULE: crypto-native (hookCryptoNative) =====================
// ==========================================
// NATIVE CRYPTO HOOKS (BoringSSL / zlib)
// ==========================================
// Native-only malware often decrypts/decompresses second-stage payloads in libcrypto.so
// (BoringSSL EVP/AES) and libz.so, entirely skipping the Java JCA layer that a pure-Java
// hook would catch. We observe the PLAINTEXT (decrypted / decompressed output) plus the
// key/iv material, run it through checkAndLog against the evasion lexicon, and hand any
// buffer to dumpBuffer (which classifies dex/elf/zip magic and, if DUMP_PAYLOADS, writes
// it to DUMP_DIR). Detection-only: nothing here mutates the sample.
//
// GATING: every hook is gated by isTargetCaller(this.returnAddress) so we ignore framework
// crypto (GMS, TLS libs) when TARGET_MODULES is set. These are moderate-frequency calls
// (per crypto block / per payload), NOT per-syscall hot paths, so caller gating suffices.
// We additionally content-gate: we only read/preview/scan when a positive output length was
// produced (outlen > 0), so an empty or failed crypto op emits nothing. Buffer previews are
// bounded by CRYPTO_PREVIEW_CAP to keep hex formatting cheap on large payloads.

var CRYPTO_PREVIEW_CAP = 256; // max bytes hex-previewed / scanned per crypto output buffer

// Read up to `cap` bytes at `ptrBuf` as a printable string for lexicon matching. Null-safe and
// bounded; readByteArray gives us raw bytes without a NUL-termination assumption (ciphertext
// output rarely NUL-terminates). We keep only printable-ish bytes so checkAndLog sees strings.
function cryptoReadForScan(ptrBuf, len) {
    try {
        if (ptrBuf == null || ptrBuf.isNull() || len <= 0) return "";
        var scan = len < CRYPTO_PREVIEW_CAP ? len : CRYPTO_PREVIEW_CAP;
        var buf = ptrBuf.readByteArray(scan);
        if (!buf) return "";
        var bytes = new Uint8Array(buf);
        var chars = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i];
            if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) chars.push(b);
        }
        return String.fromCharCode.apply(null, chars);
    } catch (e) { return ""; }
}

// Inspect a produced crypto/decompression output buffer: classify magic + hex preview via the
// shared dumpBuffer helper, then scan the printable content against the evasion lexicon.
function cryptoInspectOutput(tag, ptrBuf, len, context) {
    if (ptrBuf == null || ptrBuf.isNull() || len <= 0) return;

    var previewLen = len < CRYPTO_PREVIEW_CAP ? len : CRYPTO_PREVIEW_CAP;

    // payloadMagic reads 4 leading bytes; only classify once at least 4 bytes were produced so
    // we never inspect past the freshly-written region.
    var magic = null;
    if (len >= 4) { try { magic = payloadMagic(ptrBuf); } catch (e) {} }

    // A recognized payload magic (dex/cdex/elf/zip) coming straight out of a decrypt/decompress
    // is itself a strong second-stage indicator, so surface it even without a lexicon hit.
    var signature = "cryptomagic|" + tag + "|" + len + "|" + (magic || "");
    if (magic && !ALERT_HISTORY[signature]) {
        markSeen(signature);
        console.log("\n" + C.PURPLE + "[!] [CRYPTO] " + tag + " produced " + len +
                    " bytes; payload magic=" + magic + C.RESET);
        try {
            console.log(C.YELLOW + "    -> Hex: " + hexPreview(ptrBuf, previewLen) + C.RESET);
        } catch (e) {}
        console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                    formatBacktrace(getNativeBacktrace(context)) + C.RESET);
    }

    try { dumpBuffer(tag, ptrBuf, len); } catch (e) {}

    var scanStr = cryptoReadForScan(ptrBuf, len);
    if (scanStr) {
        checkAndLog(tag, scanStr, function () { return getNativeBacktrace(context); });
    }
}

// hexPreview a key/iv-style buffer of unknown-but-small length (no length arg is passed to the
// *Init/AES key-setup functions). Bounded to `maxLen` bytes. Null-safe.
function cryptoPreviewKeyMaterial(label, ptrBuf, maxLen) {
    try {
        if (ptrBuf == null || ptrBuf.isNull()) return;
        var n = maxLen > 0 ? maxLen : 16;
        console.log(C.YELLOW + "    -> " + label + " (" + n + "B): " + hexPreview(ptrBuf, n) + C.RESET);
    } catch (e) {}
}

function hookCryptoNative() {
    // ---- BoringSSL EVP *Update: decrypt/encrypt/cipher block updates ----
    // Signature: int EVP_(De|En|)cryptUpdate(ctx, out, int *outlen, in, inlen)
    //   out=args[1], outlen ptr=args[2], in=args[3], inlen=args[4]
    // The PLAINTEXT (for decrypt) or output lands in `out`; its true length is *outlen, valid
    // only AFTER the call. Capture out + outlen ptr on enter, read *outlen bytes on leave.
    ["EVP_DecryptUpdate", "EVP_EncryptUpdate", "EVP_CipherUpdate"].forEach(function (fn) {
        var p = getExportSafe("libcrypto.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.outPtr = args[1];
                    this.outLenPtr = args[2];
                    // this.context is the Interceptor CpuContext; save it for the onLeave backtrace.
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    if (retval.toInt32() !== 1) return; // BoringSSL returns 1 on success
                    var outLen = 0;
                    try {
                        if (this.outLenPtr && !this.outLenPtr.isNull()) {
                            outLen = this.outLenPtr.readInt();
                        }
                    } catch (e) { return; }
                    if (outLen > 0) {
                        cryptoInspectOutput("CRYPTO:" + fn, this.outPtr, outLen, this.ctx);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Native Crypto: " + fn + " (libcrypto.so)" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- BoringSSL EVP *Final_ex: flush the last (padded) block ----
    // Signature: int EVP_(De|En|)cryptFinal_ex(ctx, out, int *outlen)
    //   out=args[1], outlen ptr=args[2]. Same capture-on-enter / read-on-leave pattern.
    ["EVP_DecryptFinal_ex", "EVP_EncryptFinal_ex", "EVP_CipherFinal_ex"].forEach(function (fn) {
        var p = getExportSafe("libcrypto.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.outPtr = args[1];
                    this.outLenPtr = args[2];
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    if (retval.toInt32() !== 1) return;
                    var outLen = 0;
                    try {
                        if (this.outLenPtr && !this.outLenPtr.isNull()) {
                            outLen = this.outLenPtr.readInt();
                        }
                    } catch (e) { return; }
                    if (outLen > 0) {
                        cryptoInspectOutput("CRYPTO:" + fn, this.outPtr, outLen, this.ctx);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Native Crypto: " + fn + " (libcrypto.so)" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- BoringSSL EVP *Init_ex: capture key + iv material ----
    // Signature: int EVP_(De|En|)cryptInit_ex(ctx, const EVP_CIPHER *cipher, ENGINE *impl,
    //                                         const unsigned char *key, const unsigned char *iv)
    //   cipher=args[1], key=args[3], iv=args[4]. No key/iv length is passed, so we preview a
    //   fixed cap: 32 bytes covers up to AES-256 keys, 16 bytes covers a standard IV/GCM nonce.
    //   Includes EVP_CipherInit_ex (same signature) to match the Cipher* Update/Final coverage.
    ["EVP_DecryptInit_ex", "EVP_EncryptInit_ex", "EVP_CipherInit_ex"].forEach(function (fn) {
        var p = getExportSafe("libcrypto.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var cipherPtr = args[1];
                    var keyPtr = args[3];
                    var ivPtr = args[4];
                    // Callers may pass key/iv as NULL on a first-init/second-init split; the
                    // preview helper is null-safe and simply emits nothing for a NULL buffer.
                    console.log("\n" + C.PURPLE + "[!] [CRYPTO] " + fn +
                                " (cipher=" + cipherPtr + ")" + C.RESET);
                    cryptoPreviewKeyMaterial("key", keyPtr, 32);
                    cryptoPreviewKeyMaterial("iv", ivPtr, 16);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                                formatBacktrace(getNativeBacktrace(this.context)) + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked Native Crypto: " + fn + " (libcrypto.so)" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- Low-level AES key schedule setup ----
    // Signature: int AES_set_(en|de)crypt_key(const unsigned char *key, int bits, AES_KEY *out)
    //   key=args[0], bits=args[1]. Preview bits/8 key bytes (capped at 32B = AES-256).
    ["AES_set_encrypt_key", "AES_set_decrypt_key"].forEach(function (fn) {
        var p = getExportSafe("libcrypto.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var keyPtr = args[0];
                    var bits = 0;
                    try { bits = args[1].toInt32(); } catch (e) {}
                    var keyBytes = bits > 0 ? (bits / 8) : 32;
                    if (keyBytes > 32) keyBytes = 32;
                    console.log("\n" + C.PURPLE + "[!] [CRYPTO] " + fn + " (bits=" + bits + ")" + C.RESET);
                    cryptoPreviewKeyMaterial("aes_key", keyPtr, keyBytes);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                                formatBacktrace(getNativeBacktrace(this.context)) + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked Native Crypto: " + fn + " (libcrypto.so)" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- zlib inflate: streaming decompression ----
    // Signature: int inflate(z_streamp strm, int flush). The decompressed bytes are written to
    // strm->next_out; the amount produced = (avail_out before) - (avail_out after). The z_stream
    // layout is { Bytef* next_in; uInt avail_in; uLong total_in; Bytef* next_out; uInt avail_out; ... }.
    // On LP64 (uLong/ptr = 8): next_in@0, avail_in@8, a 4-byte pad, total_in@16, next_out@24,
    // avail_out@32. On ILP32 (all fields 4 bytes): next_out@12, avail_out@16. We snapshot next_out +
    // avail_out on enter and diff avail_out on leave to locate exactly the freshly-produced window.
    // Struct reads are wrapped in try/catch so a layout mismatch degrades to a skip, not a crash.
    (function () {
        var p = getExportSafe("libz.so", "inflate");
        if (!p) { p = getExportSafe("libc.so", "inflate"); } // some ROMs fold zlib into libc
        if (!p) return;
        var wide = Process.pointerSize === 8;
        var NEXT_OUT_OFF = wide ? 24 : 12;
        var AVAIL_OUT_OFF = wide ? 32 : 16;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.strm = args[0];
                    this.startOut = null;
                    this.availBefore = 0;
                    this.ctx = this.context;
                    try {
                        if (this.strm && !this.strm.isNull()) {
                            this.startOut = this.strm.add(NEXT_OUT_OFF).readPointer();
                            this.availBefore = this.strm.add(AVAIL_OUT_OFF).readU32();
                        } else {
                            this.skip = true;
                        }
                    } catch (e) { this.skip = true; }
                },
                onLeave: function (retval) {
                    if (this.skip || !this.startOut || this.startOut.isNull()) return;
                    // inflate returns Z_OK(0) or Z_STREAM_END(1) on progress; negatives are errors.
                    if (retval.toInt32() < 0) return;
                    var availAfter = 0;
                    try { availAfter = this.strm.add(AVAIL_OUT_OFF).readU32(); } catch (e) { return; }
                    var produced = this.availBefore - availAfter;
                    // inflate fires on ALL framework decompression (PNG/asset/APK) - an inherently
                    // hot path. Content-gate to real payloads (dex/elf/zip magic) or when dumping,
                    // so ordinary decompression pays only a 4-byte magic sniff, not a full inspect.
                    if (produced > 0 && (DUMP_PAYLOADS || payloadMagic(this.startOut) !== null)) {
                        cryptoInspectOutput("CRYPTO:inflate", this.startOut, produced, this.ctx);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Native Crypto: inflate (libz.so)" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook inflate: " + e.message + C.RESET);
        }
    })();

    // ---- zlib uncompress: one-shot decompression ----
    // Signature: int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen)
    //   dest=args[0], destLen ptr=args[1]. On success *destLen holds the decompressed size; read
    //   it on leave and inspect dest. uLongf is unsigned long: 8 bytes on LP64, 4 bytes on ILP32.
    (function () {
        var p = getExportSafe("libz.so", "uncompress");
        if (!p) { p = getExportSafe("libc.so", "uncompress"); }
        if (!p) return;
        var wide = Process.pointerSize === 8;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.destPtr = args[0];
                    this.destLenPtr = args[1];
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    if (retval.toInt32() !== 0) return; // Z_OK == 0
                    var destLen = 0;
                    try {
                        if (this.destLenPtr && !this.destLenPtr.isNull()) {
                            destLen = wide ? this.destLenPtr.readU64().toNumber()
                                           : this.destLenPtr.readU32();
                        }
                    } catch (e) { return; }
                    // Same hot-path gate as inflate: only inspect decompressed output that carries
                    // a payload magic (or when dumping is on).
                    if (destLen > 0 && (DUMP_PAYLOADS || payloadMagic(this.destPtr) !== null)) {
                        cryptoInspectOutput("CRYPTO:uncompress", this.destPtr, destLen, this.ctx);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Native Crypto: uncompress (libz.so)" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Failed to hook uncompress: " + e.message + C.RESET);
        }
    })();

    console.log(C.GREEN + "[+] Native crypto/zlib hooks installed (libcrypto.so, libz.so)" + C.RESET);
}

// ===================== MODULE: memory-unpacking (hookMemoryUnpacking) =====================
// ==========================================
// MEMORY-UNPACKING PRIMITIVES
// mprotect / mmap / mmap64 / memfd_create / munmap / remap_file_pages
// ==========================================

// PROT_* and MAP_* constants (Linux/Android, arm64 + x86_64 share these values).
var PROT_EXEC = 0x4;
var PROT_WRITE = 0x2;
var PROT_READ = 0x1;
var MAP_ANONYMOUS = 0x20; // MAP_ANON on Android/Linux

// Render a protection bitmask as "rwx" (dashes for missing bits) for readable logs.
function protStr(prot) {
    return ((prot & PROT_READ) ? "r" : "-") +
           ((prot & PROT_WRITE) ? "w" : "-") +
           ((prot & PROT_EXEC) ? "x" : "-");
}

// Consider a dump when a region becomes executable and its magic looks like real code/archive.
// dumpBuffer() itself only writes to DUMP_DIR when DUMP_PAYLOADS is set; otherwise it just logs
// magic + size + preview, so this call is safe even when payload dumping is disabled.
function maybeDumpExecRegion(tag, addr, len) {
    if (!addr || addr.isNull() || len <= 0) return;
    try {
        var magic = payloadMagic(addr);
        if (magic) {
            dumpBuffer(tag + ":" + magic, addr, len);
        }
    } catch (e) {}
}

function hookMemoryUnpacking() {

    if (!HOOK_MEMORY_PROTECTION) {
        console.log(C.YELLOW + "[*] Memory hooks (mmap/mprotect/munmap) DISABLED (prevents JIT crash)." + C.RESET);
    }

    // ---- mprotect --------------------------------------------------------
    // args: addr, len, prot. GATING: this is extremely hot, so we LOG ONLY when the requested
    // prot contains PROT_EXEC. We additionally read the region's CURRENT protection on enter to
    // detect a W->X transition (writable page flipped to executable = classic unpacker) and RWX,
    // the strongest unpacker signals. Non-exec mprotect (the common case) is dropped silently.
    var mprotectPtr = getExportSafe("libc.so", "mprotect");
    if (HOOK_MEMORY_PROTECTION && mprotectPtr) {
        Interceptor.attach(mprotectPtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                this.prot = args[2].toInt32();
                // Content gate: ignore anything that does not request execute permission.
                if ((this.prot & PROT_EXEC) === 0) { this.skip = true; return; }
                this.skip = false;

                this.addr = args[0];
                // len is size_t: use toUInt32() so a large mapping does not truncate to a
                // negative int32 and silently defeat the len <= 0 guard in maybeDumpExecRegion.
                this.len = args[1].toUInt32();

                // Was the region writable BEFORE this call? If so, W->X transition.
                this.wasWritable = false;
                try {
                    var range = Process.findRangeByAddress(this.addr);
                    if (range && range.protection && range.protection.indexOf("w") !== -1) {
                        this.wasWritable = true;
                    }
                } catch (e) {}

                var isRWX = (this.prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ===
                            (PROT_READ | PROT_WRITE | PROT_EXEC);

                var ctx = this.context;
                var bt = formatBacktrace(getNativeBacktrace(ctx));
                var sig = "mprotect|" + this.addr + "|" + this.prot;

                if (!ALERT_HISTORY[sig]) {
                    markSeen(sig);
                    var label = isRWX ? "RWX region (unpacker)" :
                                (this.wasWritable ? "W->X transition (unpacker)" : "region made executable");
                    console.log("\n" + C.RED + "[!] [mprotect] " + label + C.RESET);
                    console.log(C.YELLOW + "    -> addr=" + this.addr + " len=" + this.len +
                                " prot=" + protStr(this.prot) + " (0x" + this.prot.toString(16) + ")" + C.RESET);
                    try {
                        console.log(C.CYAN + "    -> preview: " + hexPreview(this.addr, 32) + C.RESET);
                    } catch (e) {}
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                }
            },
            onLeave: function (retval) {
                if (this.skip) return;
                // Only after the page is actually executable can we meaningfully sniff its magic.
                if (retval.toInt32() === 0) {
                    maybeDumpExecRegion("mprotect-exec", this.addr, this.len);
                }
            }
        });
        console.log(C.GREEN + "[+] Hooked Memory: mprotect (PROT_EXEC gated)" + C.RESET);
    }

    // ---- mmap / mmap64 ---------------------------------------------------
    // args: addr, len, prot, flags, fd, offset. GATING: mmap is extremely hot, so we LOG ONLY
    // when prot contains PROT_EXEC (executable mapping) or is fully RWX. Ordinary file/anon data
    // mappings without execute are dropped. MAP_ANONYMOUS is noted (anon+exec = staged shellcode).
    ["mmap", "mmap64"].forEach(function (fn) {
        if (!HOOK_MEMORY_PROTECTION) return;
        var mmapPtr = getExportSafe("libc.so", fn);
        if (!mmapPtr) return;
        Interceptor.attach(mmapPtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                this.prot = args[2].toInt32();
                if ((this.prot & PROT_EXEC) === 0) { this.skip = true; return; } // content gate
                this.skip = false;

                this.len = args[1].toUInt32(); // size_t: avoid negative int32 truncation
                this.flags = args[3].toInt32();
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (this.skip) return;
                // MAP_FAILED is (void*)-1; compare pointers directly (toInt32() would rely on a
                // 64-bit->int32 truncation of the all-ones pointer to happen to equal -1).
                if (retval.isNull() || retval.equals(ptr("-1"))) return;

                var isRWX = (this.prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ===
                            (PROT_READ | PROT_WRITE | PROT_EXEC);
                var isAnon = (this.flags & MAP_ANONYMOUS) !== 0;

                var sig = "mmap|" + retval + "|" + this.prot + "|" + this.flags;
                if (!ALERT_HISTORY[sig]) {
                    markSeen(sig);
                    var label = isRWX ? "RWX mapping (unpacker)" : "executable mapping";
                    if (isAnon) label += " [MAP_ANONYMOUS - fileless]";
                    console.log("\n" + C.RED + "[!] [" + fn + "] " + label + C.RESET);
                    console.log(C.YELLOW + "    -> base=" + retval + " len=" + this.len +
                                " prot=" + protStr(this.prot) + " (0x" + this.prot.toString(16) + ")" +
                                " flags=0x" + this.flags.toString(16) + C.RESET);
                    try {
                        console.log(C.CYAN + "    -> preview: " + hexPreview(retval, 32) + C.RESET);
                    } catch (e) {}
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                                formatBacktrace(getNativeBacktrace(this.ctx)) + C.RESET);
                }
                maybeDumpExecRegion(fn + "-exec", retval, this.len);
            }
        });
        console.log(C.GREEN + "[+] Hooked Memory: " + fn + " (PROT_EXEC gated)" + C.RESET);
    });

    // ---- memfd_create ----------------------------------------------------
    // arg0 = name. Fileless staging primitive: an anonymous in-memory file often used to stage a
    // decrypted dex/elf then execute it (memfd + mmap PROT_EXEC). Low frequency, so always log.
    var memfdPtr = getExportSafe("libc.so", "memfd_create");
    if (memfdPtr) {
        Interceptor.attach(memfdPtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                this.skip = false;
                this.name = readStrSafe(args[0]);
                this.ctx = this.context;
            },
            onLeave: function (retval) {
                if (this.skip) return;
                var sig = "memfd_create|" + this.name;
                if (!ALERT_HISTORY[sig]) {
                    markSeen(sig);
                    console.log("\n" + C.PURPLE + "[!] [memfd_create] Fileless in-memory staging: name=\"" +
                                this.name + "\" -> fd=" + retval.toInt32() + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                                formatBacktrace(getNativeBacktrace(this.ctx)) + C.RESET);
                }
                // Feed the name through the lexicon (may hit dex/frida/etc. artifacts).
                // Capture ctx in a local: inside the trace closure `this` is NOT the Interceptor
                // context (checkAndLog invokes the callback bare).
                var ctx = this.ctx;
                checkAndLog("memfd_create", this.name, function () { return getNativeBacktrace(ctx); });
            }
        });
        console.log(C.GREEN + "[+] Hooked Memory: memfd_create" + C.RESET);
    }

    // ---- munmap / remap_file_pages --------------------------------------
    // Anti-dump: unpackers often unmap or remap the region that held the decrypted payload right
    // after use so a later memory scrape finds nothing. Both are far lower frequency than mmap;
    // gated by isTargetCaller and deduped, so they cannot flood.
    var munmapPtr = getExportSafe("libc.so", "munmap");
    if (HOOK_MEMORY_PROTECTION && munmapPtr) {
        Interceptor.attach(munmapPtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) return;
                var addr = args[0];
                var len = args[1].toUInt32(); // size_t
                // Only surface unmaps of currently-executable regions (payload teardown); a plain
                // data unmap is noise. If we cannot resolve the range, stay quiet.
                var isExec = false;
                try {
                    var range = Process.findRangeByAddress(addr);
                    isExec = !!(range && range.protection && range.protection.indexOf("x") !== -1);
                } catch (e) {}
                if (!isExec) return;

                var sig = "munmap|" + addr + "|" + len;
                if (!ALERT_HISTORY[sig]) {
                    markSeen(sig);
                    var ctx = this.context;
                    console.log("\n" + C.PURPLE + "[!] [munmap] Executable region unmapped (possible anti-dump): addr=" +
                                addr + " len=" + len + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                                formatBacktrace(getNativeBacktrace(ctx)) + C.RESET);
                }
            }
        });
        console.log(C.GREEN + "[+] Hooked Memory: munmap (exec regions only)" + C.RESET);
    }

    var remapPtr = getExportSafe("libc.so", "remap_file_pages");
    if (HOOK_MEMORY_PROTECTION && remapPtr) {
        Interceptor.attach(remapPtr, {
            onEnter: function (args) {
                if (!isTargetCaller(this.returnAddress)) return;
                var addr = args[0];
                var size = args[1].toUInt32(); // size_t
                var sig = "remap_file_pages|" + addr;
                if (!ALERT_HISTORY[sig]) {
                    markSeen(sig);
                    var ctx = this.context;
                    console.log("\n" + C.PURPLE + "[!] [remap_file_pages] Non-linear page remap (possible anti-dump): addr=" +
                                addr + " size=" + size + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " +
                                formatBacktrace(getNativeBacktrace(ctx)) + C.RESET);
                }
            }
        });
        console.log(C.GREEN + "[+] Hooked Memory: remap_file_pages" + C.RESET);
    }
}

// ===================== MODULE: reflection (hookReflection) =====================
// ==========================================
// JAVA REFLECTION HOOKS
// ==========================================

// Malware hides calls behind java.lang.reflect to defeat static analysis and simple Java hooks:
// Method.invoke / Class.forName / ClassLoader.loadClass / Constructor.newInstance / Field access.
// Detection-only. Only the reflection ENTRY POINTS listed below are instrumented (never every
// Method/Class API) to avoid recursing through our own hook machinery and to keep overhead bounded.
//
// GATING: Method.invoke, ClassLoader.loadClass and Field.get/set are extremely hot in a normal
// Android app (the framework itself drives them constantly). We therefore let checkAndLog be the
// gate: the noisy PURPLE header + Java backtrace (logReflect) is emitted ONLY when the class/
// method/field name actually matches the evasion lexicon. On a non-match we do nothing beyond the
// name build, so these hooks never flood the console or stall the app.
function hookReflection() {
    if (!Java.available) {
        console.log(C.YELLOW + "[!] Java is not available. Skipping reflection hooks." + C.RESET);
        return;
    }

    Java.perform(function() {
        // Resolve Log/Exception independently so one missing class does not disable the other.
        var Log = null, Exception = null;
        try {
            Log = Java.use("android.util.Log");
        } catch (e) {
            console.log(C.YELLOW + "[-] Reflection: could not resolve android.util.Log for backtraces: " + e.message + C.RESET);
        }
        try {
            Exception = Java.use("java.lang.Exception");
        } catch (e) {
            console.log(C.YELLOW + "[-] Reflection: could not resolve java.lang.Exception for backtraces: " + e.message + C.RESET);
        }

        // Short Java backtrace, matching the file's logDCL/logNativeLoad convention. Wrapped so a
        // failure to build the stack never breaks the underlying reflection call.
        function reflectBacktrace() {
            if (!Log || !Exception) return "[Java Backtrace unavailable]";
            try {
                var instance = Exception.$new("ReflectionTrace");
                var stack = Log.getStackTraceString(instance).split('\n');
                return stack.slice(1, 8).join('\n    ');
            } catch (e) {
                return "[Java Backtrace unavailable]";
            }
        }

        // Only ever called AFTER checkAndLog has confirmed a lexicon match, so building the Java
        // stack here is bounded to genuine hits.
        function logReflect(tag, detail) {
            var bt = reflectBacktrace();
            
            // Deduplicate: If this exact reflection call originated from this exact stack trace
            // before, silently ignore it to prevent flooding.
            var sig = "reflect|" + tag + "|" + detail + "|" + bt;
            if (ALERT_HISTORY[sig]) return;
            markSeen(sig);

            console.log("\n" + C.PURPLE + "[!] [REFLECTION] " + tag + C.RESET);
            if (detail) console.log(C.YELLOW + "    -> " + detail + C.RESET);
            console.log(C.BLUE + "    -> Java Backtrace:\n    " + bt + C.RESET);
        }

        // --- java.lang.reflect.Method.invoke ---
        try {
            var Method = Java.use("java.lang.reflect.Method");
            Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;').implementation = function(obj, argArr) {
                try {
                    // `this` is the Java Method wrapper here (valid inside a Frida implementation),
                    // NOT an Interceptor context. getName()/getDeclaringClass() are the correct API.
                    var declClass = "";
                    try { declClass = this.getDeclaringClass().getName(); } catch (e) {}
                    var mName = "";
                    try { mName = this.getName(); } catch (e) {}
                    var fqmn = declClass + "." + mName;
                    // fqmn already contains declClass, so a single checkAndLog covers both.
                    if (checkAndLog("Reflection Method.invoke", fqmn, null)) {
                        logReflect("Method.invoke -> " + fqmn, null);
                    }
                } catch (e) {}
                return this.invoke(obj, argArr);
            };
            console.log(C.GREEN + "[+] Hooked reflection: Method.invoke" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook Method.invoke: " + e.message + C.RESET);
        }

        // --- java.lang.Class.forName ---
        try {
            var Clazz = Java.use("java.lang.Class");
            try {
                Clazz.forName.overload('java.lang.String').implementation = function(name) {
                    if (checkAndLog("Reflection Class.forName", "" + name, null)) {
                        logReflect("Class.forName", "" + name);
                    }
                    return this.forName(name);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Class.forName(String) overload unavailable: " + e.message + C.RESET);
            }
            try {
                Clazz.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader').implementation = function(name, init, loader) {
                    if (checkAndLog("Reflection Class.forName", "" + name, null)) {
                        logReflect("Class.forName", "" + name);
                    }
                    return this.forName(name, init, loader);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Class.forName(String,boolean,ClassLoader) overload unavailable: " + e.message + C.RESET);
            }
            // NOTE: the (Class, String) caller-context overload from the authored version was
            // dropped - it is not part of Android's libcore java.lang.Class API, so it never
            // resolves (and this.forName(caller, name) would be an invalid dispatch anyway).
            console.log(C.GREEN + "[+] Hooked reflection: Class.forName" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook Class.forName: " + e.message + C.RESET);
        }

        // --- java.lang.ClassLoader.loadClass ---
        try {
            var CL = Java.use("java.lang.ClassLoader");
            try {
                CL.loadClass.overload('java.lang.String').implementation = function(name) {
                    if (checkAndLog("Reflection ClassLoader.loadClass", "" + name, null)) {
                        logReflect("ClassLoader.loadClass", "" + name);
                    }
                    return this.loadClass(name);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] ClassLoader.loadClass(String) overload unavailable: " + e.message + C.RESET);
            }
            // Protected (String, boolean) form - Frida can still bind it; wrap defensively.
            try {
                CL.loadClass.overload('java.lang.String', 'boolean').implementation = function(name, resolve) {
                    if (checkAndLog("Reflection ClassLoader.loadClass", "" + name, null)) {
                        logReflect("ClassLoader.loadClass", "" + name);
                    }
                    return this.loadClass(name, resolve);
                };
            } catch (e) {}
            console.log(C.GREEN + "[+] Hooked reflection: ClassLoader.loadClass" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook ClassLoader.loadClass: " + e.message + C.RESET);
        }

        // --- java.lang.reflect.Constructor.newInstance ---
        try {
            var Constructor = Java.use("java.lang.reflect.Constructor");
            // newInstance(Object...) lowers to a single [Ljava.lang.Object; overload.
            Constructor.newInstance.overload('[Ljava.lang.Object;').implementation = function(argArr) {
                try {
                    var declClass = "";
                    try { declClass = this.getDeclaringClass().getName(); } catch (e) {}
                    if (checkAndLog("Reflection Constructor.newInstance", declClass, null)) {
                        logReflect("Constructor.newInstance -> " + declClass, null);
                    }
                } catch (e) {}
                return this.newInstance(argArr);
            };
            console.log(C.GREEN + "[+] Hooked reflection: Constructor.newInstance" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook Constructor.newInstance: " + e.message + C.RESET);
        }

        // --- java.lang.reflect.Field get/set/setAccessible ---
        try {
            var Field = Java.use("java.lang.reflect.Field");

            function fieldName(self) {
                var declClass = "";
                try { declClass = self.getDeclaringClass().getName(); } catch (e) {}
                var fName = "";
                try { fName = self.getName(); } catch (e) {}
                return declClass + "." + fName;
            }

            // NOTE: Field.get / Field.set are deliberately NOT hooked. They are among the hottest
            // Java paths (Gson/Jackson/Kotlin serialization walk every field), and building the
            // declaring-class + field name on every call - two JNI crossings + a regex - adds real
            // overhead to a benign framework hot path for little signal. setAccessible (below) is
            // the actual evasion tell (forcing access to private/@hide members) and is far less hot.

            // setAccessible: single-Field instance form. The bulk AccessibleObject.setAccessible
            // static form is intentionally left alone to avoid noisy/broad framework matches.
            try {
                Field.setAccessible.overload('boolean').implementation = function(flag) {
                    var fqfn = fieldName(this);
                    if (checkAndLog("Reflection Field.setAccessible", fqfn, null)) {
                        logReflect("Field.setAccessible(" + flag + ") -> " + fqfn, null);
                    }
                    return this.setAccessible(flag);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Field.setAccessible overload unavailable: " + e.message + C.RESET);
            }

            console.log(C.GREEN + "[+] Hooked reflection: Field.setAccessible" + C.RESET);
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook Field APIs: " + e.message + C.RESET);
        }

        console.log(C.GREEN + "[+] Hooked Java reflection entry points" + C.RESET);
    });
}

// ===================== MODULE: anti-debug-native (hookAntiDebugNative) =====================
// ==========================================
// NATIVE ANTI-DEBUG / PROCESS PRIMITIVES
// ==========================================

// Signal numbers commonly abused by anti-debug handlers (installing a handler for these lets a
// sample "catch" a debugger's SIGTRAP/SIGILL or crash-on-attach and take an evasive branch).
var ANTIDBG_SIGNALS = { 4: "SIGILL", 5: "SIGTRAP", 11: "SIGSEGV" };

// prctl options we care about (from <sys/prctl.h>): PR_SET_DUMPABLE flips ptrace-attachability;
// PR_SET_NAME/PR_GET_NAME are used to read/rename threads to scan for/hide "gum-js-loop", "gmain",
// "pool-frida" watchdog thread names.
var PR_SET_NAME = 15, PR_GET_NAME = 16, PR_SET_DUMPABLE = 4;

// gettimeofday/clock_gettime are EXTREMELY hot (called on nearly every frame / syscall wrapper).
// CHOICE: we do NOT attach a per-call logging Interceptor to them - that would flood the console
// and add no real signal, since a single timing read is not itself a detection. Instead we keep a
// cheap sampled counter behind a default-off flag; when TIMING_SAMPLING is enabled we only emit one
// aggregated line every TIMING_SAMPLE_EVERY calls. Left off by default so timing hooks cost nothing.
var TIMING_SAMPLING = false;
var TIMING_SAMPLE_EVERY = 100000;
var _timingCounts = { clock_gettime: 0, gettimeofday: 0 };

// Backtrace-free dedup for the anti-debug alerts. Reuses the shared ALERT_HISTORY/markSeen store.
// Returns true if this signature has already been reported (caller should skip); false the first
// time (and records it). NOTE: relies on the module-level markSeen()/ALERT_HISTORY defined earlier
// in nativeDecloaker.js - do not redefine them here.
function _antiDbgSeen(sig) {
    if (ALERT_HISTORY[sig]) return true;
    markSeen(sig);
    return false;
}

function hookAntiDebugNative() {
    // ---- self-debug / process forks: fork / vfork / __clone / clone ----
    // Malware forks a child to ptrace(PTRACE_ATTACH) its own parent (a debugger can only attach
    // once), or spawns a watchdog process. Not hot enough to need content gating; module-gated.
    ["fork", "vfork", "__clone", "clone"].forEach(function(fn) {
        var p = getExportSafe("libc.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    // Compute the backtrace once and reuse it for both the dedup key and the log
                    // (the original computed it twice per event).
                    var bt = formatBacktrace(getNativeBacktrace(this.context));
                    var sig = "antidbg-fork|" + fn + "|" + bt;
                    if (_antiDbgSeen(sig)) return;
                    console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] Self-debug/watchdog fork primitive: " + fn + "()" + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: " + fn + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- prctl: dumpable flip + thread-name read/spoof ----
    // Gated: only logs the specific options of interest, so ordinary prctl traffic is ignored.
    // prctl(int option, unsigned long arg2, ...) -> option=args[0], arg2=args[1].
    var prctlPtr = getExportSafe("libc.so", "prctl");
    if (prctlPtr) {
        try {
            Interceptor.attach(prctlPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.opt = args[0].toInt32();
                    this.arg1 = args[1];
                    this.nameBuf = null;
                    this.ctx = this.context;

                    if (this.opt === PR_SET_DUMPABLE && this.arg1.toInt32() === 0) {
                        // dumpable=0 blocks ptrace attach and /proc/pid/mem reads (anti-debug).
                        var bt = formatBacktrace(getNativeBacktrace(this.ctx));
                        var sig = "antidbg-prctl-dumpable|" + bt;
                        if (_antiDbgSeen(sig)) return;
                        console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] prctl(PR_SET_DUMPABLE, 0) - blocking debugger attach." + C.RESET);
                        console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                    } else if (this.opt === PR_SET_NAME) {
                        // Renaming a thread - malware hides its watchdog, or renames to check names.
                        var nm = readStrSafe(this.arg1, 16); // thread names are capped at 16 bytes (TASK_COMM_LEN)
                        // Capture context into a local: inside the checkAndLog trace closure `this`
                        // is NOT the Interceptor context (checkAndLog calls the closure bare).
                        var ctx = this.ctx;
                        checkAndLog("prctl(PR_SET_NAME)", nm, function() { return getNativeBacktrace(ctx); });
                    } else if (this.opt === PR_GET_NAME) {
                        // Buffer is written by the kernel; capture it and scan on leave for frida
                        // thread-name artifacts (gum-js-loop / gmain / pool-frida).
                        this.nameBuf = this.arg1;
                    }
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    if (this.opt === PR_GET_NAME && this.nameBuf && !this.nameBuf.isNull()) {
                        var nm = readStrSafe(this.nameBuf, 16);
                        var ctx = this.ctx;
                        var match = checkAndLog("prctl(PR_GET_NAME)", nm, function() { return getNativeBacktrace(ctx); });
                        // Spoof only when the resolved thread name is a genuine frida artifact and
                        // active bypass is on; overwrite the returned name so the scan comes back clean.
                        if (match && ACTIVE_BYPASS && pathIsSpoofable(nm)) {
                            try {
                                this.nameBuf.writeUtf8String("main");
                                console.log(C.RED + "    -> [BYPASS] Spoofed frida thread name '" + nm + "' -> 'main'." + C.RESET);
                            } catch (e) {}
                        }
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: prctl (DUMPABLE/SET_NAME/GET_NAME)" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook prctl: " + e.message + C.RESET);
        }
    }

    // ---- pthread_create: resolve start routine -> DebugSymbol (watchdog threads) ----
    // pthread_create(thread, attr, start_routine, arg) -> start_routine=args[2].
    var pthreadPtr = getExportSafe("libc.so", "pthread_create");
    if (pthreadPtr) {
        try {
            Interceptor.attach(pthreadPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var startRoutine = args[2];
                    var bt = formatBacktrace(getNativeBacktrace(this.context));
                    var sym = "";
                    try { sym = DebugSymbol.fromAddress(startRoutine).toString(); } catch (e) {}
                    var sig = "antidbg-pthread|" + startRoutine + "|" + sym;
                    if (_antiDbgSeen(sig)) return;
                    console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] pthread_create start_routine: " + startRoutine + (sym ? " (" + sym + ")" : "") + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                    // Also run the symbol string through the lexicon (e.g. a routine in libjiagu.so).
                    if (sym) checkAndLog("pthread_create routine", sym, null);
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: pthread_create" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook pthread_create: " + e.message + C.RESET);
        }
    }

    // ---- sigaction / signal: anti-debug handlers for SIGTRAP/SIGILL/SIGSEGV ----
    // Gated to only the anti-debug signal numbers so ordinary signal setup is ignored.
    // sigaction(int signum, ...) / signal(int signum, ...) -> signum=args[0].
    ["sigaction", "signal", "bsd_signal", "sysv_signal"].forEach(function(fn) {
        var p = getExportSafe("libc.so", fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var signum = args[0].toInt32();
                    var name = ANTIDBG_SIGNALS[signum];
                    if (!name) return; // only report the anti-debug signals
                    var bt = formatBacktrace(getNativeBacktrace(this.context));
                    var sig = "antidbg-signal|" + fn + "|" + name + "|" + bt;
                    if (_antiDbgSeen(sig)) return;
                    console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] " + fn + "() installing handler for " + name + " (" + signum + ")" + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: " + fn + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
        }
    });

    // ---- kill / tgkill / tkill: sig==0 liveness probe (a debugger/analysis parent still alive?) ----
    // Gated to sig==0 only; real signal delivery is left alone to avoid flooding.
    // kill(pid, sig) -> sig=args[1]; tgkill(tgid, tid, sig) -> sig=args[2]; tkill(tid, sig) -> sig=args[1].
    [{ fn: "kill", sigIdx: 1 }, { fn: "tgkill", sigIdx: 2 }, { fn: "tkill", sigIdx: 1 }].forEach(function(cfg) {
        var p = getExportSafe("libc.so", cfg.fn);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var signum = args[cfg.sigIdx].toInt32();
                    if (signum !== 0) return; // only the sig==0 liveness probe is of interest
                    var target = args[0].toInt32();
                    var bt = formatBacktrace(getNativeBacktrace(this.context));
                    var sig = "antidbg-kill0|" + cfg.fn + "|" + target + "|" + bt;
                    if (_antiDbgSeen(sig)) return;
                    console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] " + cfg.fn + "(pid/tid=" + target + ", sig=0) liveness probe." + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: " + cfg.fn + " (sig==0)" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook " + cfg.fn + ": " + e.message + C.RESET);
        }
    });

    // ---- getppid: parent-pid checks (is the parent zygote, or an analysis harness?) ----
    // Low frequency; dedup on backtrace so a polling loop only prints once.
    var getppidPtr = getExportSafe("libc.so", "getppid");
    if (getppidPtr) {
        try {
            Interceptor.attach(getppidPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    var ppid = retval.toInt32();
                    var bt = formatBacktrace(getNativeBacktrace(this.ctx));
                    var sig = "antidbg-getppid|" + bt;
                    if (_antiDbgSeen(sig)) return;
                    console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] getppid() -> " + ppid + " (parent-process identity check)." + C.RESET);
                    console.log(C.BLUE + "    -> Source Backtrace:\n    " + bt + C.RESET);
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: getppid" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook getppid: " + e.message + C.RESET);
        }
    }

    // ---- inotify_add_watch: watching a path (self-tamper / frida-file detection) ----
    // inotify_add_watch(fd, pathname, mask) -> pathname=args[1].
    var inotifyPtr = getExportSafe("libc.so", "inotify_add_watch");
    if (inotifyPtr) {
        try {
            Interceptor.attach(inotifyPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var watched = readStrSafe(args[1]);
                    if (!watched) return;
                    var ctx = this.context;
                    var match = checkAndLog("inotify_add_watch", watched, function() { return getNativeBacktrace(ctx); });
                    if (!match) {
                        // Even non-lexicon paths are worth a single low-noise note (dedup by path).
                        var sig = "antidbg-inotify|" + watched;
                        if (_antiDbgSeen(sig)) return;
                        console.log("\n" + C.PURPLE + "[!] [ANTI-DEBUG] inotify_add_watch watching: " + watched + C.RESET);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked Anti-Debug: inotify_add_watch" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook inotify_add_watch: " + e.message + C.RESET);
        }
    }

    // ---- clock_gettime / gettimeofday: EXTREMELY hot - default-OFF sampled counter only ----
    // See TIMING_SAMPLING note above: no per-call logging. When enabled, emits one aggregated
    // line every TIMING_SAMPLE_EVERY calls; when disabled (default) these are not attached at all.
    if (TIMING_SAMPLING) {
        ["clock_gettime", "gettimeofday"].forEach(function(fn) {
            var p = getExportSafe("libc.so", fn);
            if (!p) return;
            try {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        // No isTargetCaller / backtrace here - both are too expensive for this
                        // call rate. Just a bounded modulo counter; net cost is a single increment.
                        _timingCounts[fn]++;
                        if (_timingCounts[fn] % TIMING_SAMPLE_EVERY === 0) {
                            console.log(C.YELLOW + "[TIMING] " + fn + " sampled count: " + _timingCounts[fn] + C.RESET);
                        }
                    }
                });
                console.log(C.GREEN + "[+] Hooked (sampled) timing: " + fn + C.RESET);
            } catch (e) {
                console.log(C.RED + "[-] Failed to hook " + fn + ": " + e.message + C.RESET);
            }
        });
    } else {
        console.log(C.GREEN + "[+] Timing hooks (clock_gettime/gettimeofday) SKIPPED - too hot; enable TIMING_SAMPLING to sample." + C.RESET);
    }
}

// ===================== MODULE: property-modern (hookPropertyModern) =====================
// ==========================================
// MODERN PROPERTY-READ PATHS (bypass __system_property_get)
// ==========================================
//
// Detection-only. __system_property_get is ALREADY hooked in the initializer via
// safeAttachIO("libc.so", "__system_property_get", 0); this module covers the MODERN
// libc property APIs that malware uses to sidestep that single hook when fingerprinting
// emulator/root state (ro.kernel.qemu, ro.build.tags, ro.debuggable, ...):
//
//   - __system_property_find(name)                 name = arg0, returns prop_info*
//   - __system_property_read(pi, name_out, val_out) pi = arg0, out bufs filled AFTER call
//   - __system_property_read_callback(pi, cb, cookie) name/value delivered to cb(cookie,name,value,serial)
//
// Gating: these are NOT hot like read/mmap/clock_gettime/connect, but they still fire per
// property probe. We gate every hook with isTargetCaller(this.returnAddress) (module allowlist)
// and let checkAndLog + ALERT_HISTORY dedup so repeated identical (name,value) pairs are silent.
// No spoofing here (detection-only), so no ACTIVE_BYPASS / pathIsSpoofable path is taken.

// Trampoline registry for __system_property_read_callback: maps the ORIGINAL callback
// pointer string -> a persistent NativeCallback that inspects (name,value) then forwards
// to the original. Persisted so the NativeCallback is never GC'd while the native property
// system still holds a reference, and so identical callbacks are wrapped only once.
var PROP_CB_TRAMPOLINES = {};

function makePropReadTrampoline(origCbPtr) {
    var key = origCbPtr.toString();
    if (PROP_CB_TRAMPOLINES[key]) return PROP_CB_TRAMPOLINES[key];

    // Original signature: void cb(void *cookie, const char *name, const char *value, uint32_t serial)
    var origFn = new NativeFunction(origCbPtr, 'void', ['pointer', 'pointer', 'pointer', 'uint32']);

    var trampoline = new NativeCallback(function (cookie, namePtr, valuePtr, serial) {
        try {
            var name = readStrSafe(namePtr);
            var value = readStrSafe(valuePtr);
            // No Interceptor CpuContext inside a NativeCallback, so no reliable backtrace here;
            // pass a null trace callback (checkAndLog handles that) and combine name+value so a
            // match on either field is caught (e.g. name "ro.kernel.qemu" or value "goldfish").
            var combined = name + "=" + value;
            checkAndLog("__system_property_read_callback", combined, null);
        } catch (e) {}
        // Always forward to the real callback so the app's property read is unaffected.
        // The original returns void, so do not propagate a return value.
        origFn(cookie, namePtr, valuePtr, serial);
    }, 'void', ['pointer', 'pointer', 'pointer', 'uint32']);

    PROP_CB_TRAMPOLINES[key] = trampoline;
    return trampoline;
}

function hookPropertyModern() {
    // --- __system_property_find(name) : name = arg0, returns prop_info* -----------------
    var findPtr = getExportSafe("libc.so", "__system_property_find");
    if (findPtr) {
        try {
            Interceptor.attach(findPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var name = readStrSafe(args[0]);
                    if (!name) return;
                    var ctx = this.context;
                    checkAndLog("__system_property_find", name, function () { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked (detect): __system_property_find" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook __system_property_find: " + e.message + C.RESET);
        }
    }

    // --- __system_property_read(pi, name_out, val_out) --------------------------------
    // pi = arg0, name_out = arg1, val_out = arg2. The out buffers are only populated AFTER
    // the call, so capture the pointers on enter and read/match them on leave. The function
    // returns the value length (>0) on success and <=0 when nothing was written, so only read
    // the out buffers on a positive return to avoid logging stale/garbage buffer contents.
    var readPtr = getExportSafe("libc.so", "__system_property_read");
    if (readPtr) {
        try {
            Interceptor.attach(readPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) { this.skip = true; return; }
                    this.skip = false;
                    this.namePtr = args[1];
                    this.valuePtr = args[2];
                    this.ctx = this.context;
                },
                onLeave: function (retval) {
                    if (this.skip) return;
                    if (retval.toInt32() <= 0) return;
                    var name = readStrSafe(this.namePtr);
                    var value = readStrSafe(this.valuePtr);
                    if (!name && !value) return;
                    var ctx = this.ctx;
                    var combined = name + "=" + value;
                    checkAndLog("__system_property_read", combined, function () { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked (detect): __system_property_read" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook __system_property_read: " + e.message + C.RESET);
        }
    }

    // --- __system_property_read_callback(pi, cb, cookie) ------------------------------
    // pi = arg0, cb = arg1, cookie = arg2. The name/value are handed to
    // cb(cookie, name, value, serial). We replace the caller's callback (arg1) with a
    // persistent trampoline that inspects (name,value) then forwards to the original, so the
    // property name/value are resolved even on this modern path.
    var readCbPtr = getExportSafe("libc.so", "__system_property_read_callback");
    if (readCbPtr) {
        try {
            Interceptor.attach(readCbPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var origCb = args[1];
                    if (origCb.isNull()) return;
                    try {
                        args[1] = makePropReadTrampoline(origCb);
                    } catch (e) {
                        console.log(C.YELLOW + "[-] __system_property_read_callback trampoline failed: " + e.message + C.RESET);
                    }
                }
            });
            console.log(C.GREEN + "[+] Hooked (detect): __system_property_read_callback" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook __system_property_read_callback: " + e.message + C.RESET);
        }
    }
}

// ===================== MODULE: net-native (hookNetworkC2Native) =====================
// ==========================================
// NATIVE C2 ENDPOINT + DNS HOOKS
// ==========================================

// Parse a struct sockaddr* into a compact "ip:port" (or null for families we skip).
// Layout (Android/Linux): sa_family_t is a 2-byte host-order field at +0 (readU16 is correct
// on little-endian Android). AF_INET(2): port is network-order u16 at +2, IPv4 4 bytes at +4.
// AF_INET6(10): port network-order u16 at +2, then 4-byte flowinfo, then IPv6 16 bytes at +8.
// AF_UNIX(1) / AF_NETLINK(16) are local/kernel transports, not C2 - returned as null.
function parseSockaddrC2(addrPtr) {
    try {
        if (addrPtr == null || addrPtr.isNull()) return null;

        var family = addrPtr.readU16();

        if (family === 2) { // AF_INET
            // Port is network byte order (big-endian): combine the two bytes hi:lo.
            var pHi = addrPtr.add(2).readU8();
            var pLo = addrPtr.add(3).readU8();
            var port = ((pHi << 8) | pLo) & 0xffff;

            var b0 = addrPtr.add(4).readU8();
            var b1 = addrPtr.add(5).readU8();
            var b2 = addrPtr.add(6).readU8();
            var b3 = addrPtr.add(7).readU8();
            var ip = b0 + "." + b1 + "." + b2 + "." + b3;
            return ip + ":" + port;
        }

        if (family === 10) { // AF_INET6
            var p6Hi = addrPtr.add(2).readU8();
            var p6Lo = addrPtr.add(3).readU8();
            var port6 = ((p6Hi << 8) | p6Lo) & 0xffff;

            // 16 address bytes (at +8, after 4-byte flowinfo) as eight big-endian 16-bit
            // groups, then RFC 5952 :: compaction.
            var groups = [];
            for (var i = 0; i < 8; i++) {
                var hi = addrPtr.add(8 + i * 2).readU8();
                var lo = addrPtr.add(8 + i * 2 + 1).readU8();
                groups.push(((hi << 8) | lo) & 0xffff);
            }
            var ip6 = compactIPv6(groups);
            // Bracket the host so ip6:port stays unambiguous (e.g. [::1]:443).
            return "[" + ip6 + "]:" + port6;
        }

        // Any other family (AF_UNIX=1, AF_NETLINK=16, etc.) is not a C2 endpoint.
        return null;
    } catch (e) {
        return null;
    }
}

// Compact eight 16-bit groups into RFC 5952 form: lowercase hex, drop leading zeros,
// collapse the single longest run (length >= 2) of zero groups to "::".
function compactIPv6(groups) {
    // Locate the longest zero-run.
    var bestStart = -1, bestLen = 0;
    var curStart = -1, curLen = 0;
    for (var i = 0; i < groups.length; i++) {
        if (groups[i] === 0) {
            if (curStart === -1) { curStart = i; curLen = 1; }
            else { curLen++; }
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else {
            curStart = -1; curLen = 0;
        }
    }

    var parts = [];
    for (var j = 0; j < groups.length; j++) {
        parts.push(groups[j].toString(16));
    }

    if (bestLen >= 2) {
        var head = parts.slice(0, bestStart).join(":");
        var tail = parts.slice(bestStart + bestLen).join(":");
        return head + "::" + tail;
    }
    return parts.join(":");
}

// C2 destination + DNS resolution hooks. NOTE ON GATING: unlike the hot file/syscall hooks in
// this agent, these are deliberately NOT gated by isTargetCaller - every socket destination and
// every resolved hostname is intelligence worth capturing regardless of the calling module.
// Flooding is instead controlled by ALERT_HISTORY dedup: connect() dedups on "ip:port", DNS
// hooks dedup on the hostname, so repeated dials/lookups to the same endpoint print once. Note
// connect() is a per-socket call (not a per-byte hot path like read/recv), so per-endpoint
// dedup is sufficient to prevent flooding.
function hookNetworkC2Native() {

    // --- libc connect(): the destination of every outbound socket (CRITICAL) ---
    // Signature: int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    // addr = args[1]. No isTargetCaller gate (see note above).
    var connectPtr = getExportSafe("libc.so", "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                var endpoint = parseSockaddrC2(args[1]);
                if (!endpoint) return; // AF_UNIX/AF_NETLINK/unknown -> skipped

                var signature = "connect|" + endpoint;
                if (ALERT_HISTORY[signature]) return;
                markSeen(signature);

                // Capture the CpuContext into a local. The trace closure below must NOT
                // reference `this` - checkAndLog invokes traceCallback as a bare function, so
                // `this` would not be the Interceptor context there. Compute the backtrace once
                // and reuse it for both the console line and checkAndLog on this critical hook.
                var ctx = this.context;
                var bt = getNativeBacktrace(ctx);

                console.log("\n" + C.RED + "[!] [C2 CONNECT] Outbound socket destination: " + endpoint + C.RESET);
                console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(bt) + C.RESET);

                // Also run the endpoint through the lexicon (matches known C2/IP-echo hosts if the
                // literal IP/port ever appears in TARGET_STRINGS). checkAndLog dedups independently.
                checkAndLog("connect", endpoint, function () { return bt; });
            }
        });
        console.log(C.GREEN + "[+] Hooked C2 Endpoint: connect (libc.so)" + C.RESET);
    }

    // --- DNS resolution: hostname is the first string argument for each of these ---
    // getaddrinfo(const char *node, ...)                -> node = args[0]
    // android_getaddrinfofornet(const char *hostname,...) -> hostname = args[0]
    // gethostbyname(const char *name)                   -> name = args[0]
    var dnsFuncs = [
        { mod: "libc.so", func: "getaddrinfo" },
        { mod: "libc.so", func: "android_getaddrinfofornet" },
        { mod: "libc.so", func: "gethostbyname" }
    ];

    // `let` for block scope so each Interceptor closure keeps its own cfg (mirrors the existing
    // hookNetworkTraffic loop - `var` would share the last cfg across every hook).
    for (let i = 0; i < dnsFuncs.length; i++) {
        let cfg = dnsFuncs[i];
        let dnsPtr = getExportSafe(cfg.mod, cfg.func);
        if (!dnsPtr) continue;

        Interceptor.attach(dnsPtr, {
            onEnter: function (args) {
                // No isTargetCaller gate: every resolved hostname is worth logging.
                var host = readStrSafe(args[0]);
                if (!host) return;

                var signature = "dns|" + cfg.func + "|" + host;
                if (ALERT_HISTORY[signature]) return;
                markSeen(signature);

                // Capture context locally; the trace closure must not reference `this`.
                var ctx = this.context;
                var bt = getNativeBacktrace(ctx);

                console.log("\n" + C.CYAN + "[!] [DNS] " + cfg.func + " resolving host: " + host + C.RESET);
                console.log(C.BLUE + "    -> Source Backtrace:\n    " + formatBacktrace(bt) + C.RESET);

                // Match the resolved domain against the C2/evasion lexicon.
                checkAndLog(cfg.func, host, function () { return bt; });
            }
        });
        console.log(C.GREEN + "[+] Hooked DNS: " + cfg.func + " (" + cfg.mod + ")" + C.RESET);
    }
}

// ===================== MODULE: net-java (hookNetworkC2Java) =====================
// ==========================================
// JAVA/HIGH-LEVEL NETWORK C2 & TLS-PINNING BYPASS HOOKS
// ==========================================
// Java-layer network endpoint discovery (URL/HttpURLConnection/WebView/OkHttp/DatagramSocket)
// and TLS certificate-pinning observation. Pinning/trust NEUTRALIZATION only happens when
// ACTIVE_BYPASS is true; otherwise every hook is observe-and-log only (no MITM enabled).
// All values are routed through checkAndLog (the shared global) for lexicon matching in
// addition to the explicit console.log. Depends only on the existing globals C, checkAndLog,
// and ACTIVE_BYPASS; defines no new shared/global helpers and re-adds no existing hook.
function hookNetworkC2Java() {
    if (!Java.available) {
        console.log(C.YELLOW + "[!] Java is not available. Skipping Network C2 / pinning hooks." + C.RESET);
        return;
    }

    // Registered ONCE, lazily, the first time SSLContext.init is neutralized under ACTIVE_BYPASS.
    // Calling Java.registerClass twice with the same name throws "class already exists"; caching
    // the wrapper is what lets the bypass survive more than a single TLS handshake (the original
    // per-call registerClass aborted the bypass on the 2nd MITM'd connection).
    var _PermissiveTM = null;
    function getPermissiveTrustManager() {
        if (_PermissiveTM !== null) return _PermissiveTM;
        try {
            var X509TM = Java.use("javax.net.ssl.X509TrustManager");
            _PermissiveTM = Java.registerClass({
                name: "com.amas.decloak.PermissiveTrustManager",
                implements: [X509TM],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    // Return a plain empty JS array. Java.array("...X509Certificate", []) cannot
                    // infer an element type from an empty list and throws on some Frida versions.
                    getAcceptedIssuers: function () { return []; }
                }
            });
        } catch (e) {
            _PermissiveTM = false;
        }
        return _PermissiveTM;
    }

    Java.perform(function () {
        // Local (non-shared) Java backtrace helper for the pure-Java call sites below.
        var _Log = null, _Throwable = null;
        try {
            _Log = Java.use("android.util.Log");
            _Throwable = Java.use("java.lang.Throwable");
        } catch (e) {
            console.log(C.YELLOW + "[-] Java backtrace helpers unavailable: " + e.message + C.RESET);
        }
        function javaBacktrace(tag) {
            try {
                if (!_Log || !_Throwable) return "";
                var t = _Throwable.$new(tag);
                var stack = _Log.getStackTraceString(t).split("\n");
                return stack.slice(1, 8).join("\n    ");
            } catch (e) { return ""; }
        }

        // ---- java.net.URL.$init [full URL] ----------------------------------
        try {
            var URL = Java.use("java.net.URL");
            URL.$init.overload("java.lang.String").implementation = function (spec) {
                try {
                    console.log("\n" + C.CYAN + "[!] [NET-C2] URL(): " + spec + C.RESET);
                    checkAndLog("java.net.URL", "" + spec, null);
                } catch (e) {}
                return this.$init(spec);
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook java.net.URL.$init: " + e.message + C.RESET);
        }

        // ---- HttpURLConnectionImpl: setRequestMethod / getInputStream -------
        try {
            var HUC = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");
            try {
                HUC.setRequestMethod.overload("java.lang.String").implementation = function (method) {
                    try {
                        var url = "";
                        try { url = "" + this.getURL(); } catch (e2) {}
                        console.log("\n" + C.CYAN + "[!] [NET-C2] HttpURLConnection.setRequestMethod: " + method + " " + url + C.RESET);
                        checkAndLog("HttpURLConnection.method", method + " " + url, null);
                    } catch (e) {}
                    return this.setRequestMethod(method);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook HttpURLConnectionImpl.setRequestMethod: " + e.message + C.RESET);
            }
            try {
                HUC.getInputStream.overload().implementation = function () {
                    try {
                        var url = "";
                        try { url = "" + this.getURL(); } catch (e2) {}
                        var method = "";
                        try { method = "" + this.getRequestMethod(); } catch (e3) {}
                        var headers = "";
                        try { headers = "" + this.getRequestProperties(); } catch (e4) {}
                        console.log("\n" + C.CYAN + "[!] [NET-C2] HttpURLConnection.getInputStream: " + method + " " + url + C.RESET);
                        if (headers) console.log(C.YELLOW + "    -> Headers: " + headers + C.RESET);
                        checkAndLog("HttpURLConnection.request", method + " " + url + " " + headers, null);
                    } catch (e) {}
                    return this.getInputStream();
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook HttpURLConnectionImpl.getInputStream: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] HttpURLConnectionImpl not present (skipping): " + e.message + C.RESET);
        }

        // ---- android.webkit.WebView: loadUrl / postUrl / evaluateJavascript -
        try {
            var WebView = Java.use("android.webkit.WebView");
            try {
                WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
                    try {
                        console.log("\n" + C.CYAN + "[!] [NET-C2] WebView.loadUrl: " + url + C.RESET);
                        checkAndLog("WebView.loadUrl", "" + url, null);
                    } catch (e) {}
                    return this.loadUrl(url);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook WebView.loadUrl(String): " + e.message + C.RESET);
            }
            try {
                WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
                    try {
                        console.log("\n" + C.CYAN + "[!] [NET-C2] WebView.loadUrl (with headers): " + url + C.RESET);
                        if (headers) console.log(C.YELLOW + "    -> Headers: " + headers + C.RESET);
                        checkAndLog("WebView.loadUrl", "" + url + " " + headers, null);
                    } catch (e) {}
                    return this.loadUrl(url, headers);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook WebView.loadUrl(String,Map): " + e.message + C.RESET);
            }
            try {
                WebView.postUrl.overload("java.lang.String", "[B").implementation = function (url, data) {
                    try {
                        var len = data ? data.length : 0;
                        console.log("\n" + C.CYAN + "[!] [NET-C2] WebView.postUrl: " + url + " (postData " + len + " bytes)" + C.RESET);
                        checkAndLog("WebView.postUrl", "" + url, null);
                    } catch (e) {}
                    return this.postUrl(url, data);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook WebView.postUrl: " + e.message + C.RESET);
            }
            try {
                WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback").implementation = function (script, cb) {
                    try {
                        var preview = ("" + script);
                        if (preview.length > 300) preview = preview.substring(0, 300) + "...[TRUNCATED]";
                        console.log("\n" + C.PURPLE + "[!] [NET-C2] WebView.evaluateJavascript: " + preview + C.RESET);
                        checkAndLog("WebView.evaluateJavascript", "" + script, null);
                    } catch (e) {}
                    return this.evaluateJavascript(script, cb);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook WebView.evaluateJavascript: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] android.webkit.WebView not present (skipping): " + e.message + C.RESET);
        }

        // ---- okhttp3.Request$Builder.url / build ---------------------------
        try {
            var ReqBuilder = Java.use("okhttp3.Request$Builder");
            try {
                ReqBuilder.url.overload("java.lang.String").implementation = function (url) {
                    try {
                        console.log("\n" + C.CYAN + "[!] [NET-C2] okhttp3.Request.Builder.url: " + url + C.RESET);
                        checkAndLog("okhttp3.Request.url", "" + url, null);
                    } catch (e) {}
                    return this.url(url);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook okhttp3.Request$Builder.url(String): " + /* e.message + */ C.RESET);
            }
            try {
                ReqBuilder.build.overload().implementation = function () {
                    var req = this.build();
                    try {
                        var url = "", method = "", headers = "";
                        try { url = "" + req.url(); } catch (e2) {}
                        try { method = "" + req.method(); } catch (e3) {}
                        try { headers = "" + req.headers(); } catch (e4) {}
                        console.log("\n" + C.CYAN + "[!] [NET-C2] okhttp3.Request.build: " + method + " " + url + C.RESET);
                        if (headers) console.log(C.YELLOW + "    -> Headers: " + headers + C.RESET);
                        checkAndLog("okhttp3.Request.build", method + " " + url + " " + headers, null);
                    } catch (e) {}
                    return req;
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook okhttp3.Request$Builder.build: " + /* e.message + */ C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] okhttp3.Request$Builder not present (skipping): " + /* e.message + */ C.RESET);
        }

        // ---- okhttp3.CertificatePinner.check -------------------------------
        // Observe pinned host always. Under ACTIVE_BYPASS only, no-op (return) so the pin never
        // fails and a MITM proxy's cert is accepted. Returns void -> bare `return;` is correct.
        try {
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            // The public overloads are check(String, List) and the varargs check(String, Certificate...)
            // whose JVM type is [Ljava.security.cert.Certificate;. There is NO check(String, String).
            ["java.util.List", "[Ljava.security.cert.Certificate;"].forEach(function (listType) {
                try {
                    CertPinner.check.overload("java.lang.String", listType).implementation = function (hostname, peerCerts) {
                        try {
                            console.log("\n" + C.PURPLE + "[!] [TLS-PIN] okhttp3.CertificatePinner.check host: " + hostname + C.RESET);
                            checkAndLog("CertificatePinner.check", "" + hostname, null);
                        } catch (e) {}
                        if (ACTIVE_BYPASS) {
                            console.log(C.RED + "    -> [BYPASS] Neutralizing okhttp CertificatePinner.check (allowing MITM)." + C.RESET);
                            return;
                        }
                        return this.check(hostname, peerCerts);
                    };
                } catch (e) {
                    console.log(C.YELLOW + "[-] Could not hook CertificatePinner.check(" + listType + "): " + e.message + C.RESET);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] okhttp3.CertificatePinner not present (skipping): " + /* e.message + */ C.RESET);
        }

        // ---- Conscrypt TrustManagerImpl(s): checkServerTrusted(chain,authType) ----
        // Hook concrete framework impls (the interface has no overridable body). Observe the
        // leaf; under ACTIVE_BYPASS return without throwing so the chain is accepted.
        ["com.android.org.conscrypt.TrustManagerImpl",
         "com.google.android.gms.org.conscrypt.TrustManagerImpl"].forEach(function (tmCls) {
            try {
                var TMI = Java.use(tmCls);
                try {
                    TMI.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function (chain, authType) {
                        try {
                            var leaf = (chain && chain.length > 0) ? ("" + chain[0].getSubjectDN()) : "?";
                            console.log("\n" + C.PURPLE + "[!] [TLS-PIN] " + tmCls + ".checkServerTrusted authType=" + authType + " leaf=" + leaf + C.RESET);
                            checkAndLog(tmCls + ".checkServerTrusted", leaf, null);
                        } catch (e) {}
                        if (ACTIVE_BYPASS) {
                            console.log(C.RED + "    -> [BYPASS] Accepting server chain without validation (allowing MITM)." + C.RESET);
                            return;
                        }
                        return this.checkServerTrusted(chain, authType);
                    };
                } catch (e) {
                    console.log(C.YELLOW + "[-] Could not hook " + tmCls + ".checkServerTrusted(chain,authType): " + e.message + C.RESET);
                }
            } catch (e) {
                console.log(C.YELLOW + "[-] TrustManager impl not present (" + tmCls + "): " + /* e.message + */ C.RESET);
            }
        });

        // ---- com.android.org.conscrypt.TrustManagerImpl.verifyChain / checkTrusted ----
        // These return List<X509Certificate>. Under ACTIVE_BYPASS, short-circuit by returning
        // the presented chain as a List so pinning/validation is bypassed. Overloads vary by API
        // level, so each is guarded; the ArrayList/List uses are try/caught so a runtime failure
        // in the .implementation body never propagates into the app.
        try {
            var Conscrypt = Java.use("com.android.org.conscrypt.TrustManagerImpl");

            // verifyChain/checkTrusted signatures vary widely across API levels and Conscrypt
            // builds (arg0 is sometimes X509Certificate[], sometimes List; extra ocsp/sct/session/
            // params args come and go), so hook ALL overloads generically rather than hardcoding
            // one signature that may not exist on this device (the previous cause of the
            // "specified argument types do not match" errors).

            // Return the presented chain as a java.util.List (cast if already a List, else build one).
            function chainToList(chain) {
                var ListCls = Java.use("java.util.List");
                try { return Java.cast(chain, ListCls); } catch (e) {}
                var ArrayListCls = Java.use("java.util.ArrayList");
                var out = ArrayListCls.$new();
                try { for (var i = 0; i < chain.length; i++) out.add(chain[i]); } catch (e) {}
                return Java.cast(out, ListCls);
            }
            function firstStringArg(a) {
                for (var i = 0; i < a.length; i++) { if (typeof a[i] === "string") return a[i]; }
                return "";
            }

            ["verifyChain", "checkTrusted"].forEach(function (method) {
                try {
                    if (!Conscrypt[method]) return;
                    Conscrypt[method].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var host = firstStringArg(arguments);
                            try {
                                console.log("\n" + C.PURPLE + "[!] [TLS-PIN] Conscrypt." + method +
                                            " host/authType=" + host + C.RESET);
                                checkAndLog("Conscrypt." + method, "" + host, null);
                            } catch (e) {}
                            if (ACTIVE_BYPASS) {
                                try {
                                    var rt = "";
                                    try { rt = ov.returnType.className; } catch (e) {}
                                    console.log(C.RED + "    -> [BYPASS] Neutralizing Conscrypt." + method +
                                                " (pinning bypass)." + C.RESET);
                                    // void validators: returning nothing == accept. Chain-returning
                                    // validators: hand back the presented chain as trusted.
                                    if (rt === "void") return;
                                    return chainToList(arguments[0]);
                                } catch (e2) {
                                    console.log(C.YELLOW + "    -> [BYPASS] " + method +
                                                " fallback (running original): " + e2.message + C.RESET);
                                }
                            }
                            return ov.apply(this, arguments);
                        };
                    });
                    console.log(C.GREEN + "[+] Hooked Conscrypt." + method + " (all overloads)" + C.RESET);
                } catch (e) {
                    console.log(C.YELLOW + "[-] Could not hook Conscrypt." + method + ": " + e.message + C.RESET);
                }
            });
        } catch (e) {
            console.log(C.YELLOW + "[-] com.android.org.conscrypt.TrustManagerImpl not present: " + e.message + C.RESET);
        }

        // ---- javax.net.ssl.SSLContext.init ---------------------------------
        // Observe custom TrustManager arrays being installed. Under ACTIVE_BYPASS, replace the
        // supplied array with a single all-trusting X509TrustManager (registered once) so any
        // server cert is accepted.
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (km, tm, sr) {
                try {
                    var tmCount = tm ? tm.length : 0;
                    console.log("\n" + C.PURPLE + "[!] [TLS-PIN] SSLContext.init with " + tmCount + " TrustManager(s)." + C.RESET);
                    var bt = javaBacktrace("SSLContextInit");
                    if (bt) console.log(C.BLUE + "    -> Java Backtrace:\n    " + bt + C.RESET);
                } catch (e) {}
                if (ACTIVE_BYPASS) {
                    try {
                        var TM = getPermissiveTrustManager();
                        if (TM) {
                            console.log(C.RED + "    -> [BYPASS] Installing all-trusting X509TrustManager into SSLContext (allowing MITM)." + C.RESET);
                            var tmArr = Java.array("javax.net.ssl.TrustManager", [TM.$new()]);
                            return this.init(km, tmArr, sr);
                        }
                        console.log(C.YELLOW + "    -> [BYPASS] Permissive TrustManager unavailable; passing original TrustManagers." + C.RESET);
                    } catch (e) {
                        console.log(C.YELLOW + "    -> [BYPASS] Failed to install permissive TrustManager: " + e.message + C.RESET);
                    }
                }
                return this.init(km, tm, sr);
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook SSLContext.init: " + e.message + C.RESET);
        }

        // ---- java.net.DatagramSocket.send [UDP dest + payload] -------------
        try {
            var DatagramSocket = Java.use("java.net.DatagramSocket");
            DatagramSocket.send.overload("java.net.DatagramPacket").implementation = function (packet) {
                try {
                    var dest = "?";
                    try {
                        var addr = packet.getAddress();
                        var host = addr ? ("" + addr.getHostAddress()) : "?";
                        dest = host + ":" + packet.getPort();
                    } catch (e2) {}
                    var len = 0;
                    try { len = packet.getLength(); } catch (e3) {}
                    console.log("\n" + C.CYAN + "[!] [NET-C2] DatagramSocket.send (UDP) -> " + dest + " (" + len + " bytes)" + C.RESET);

                    // Bounded printable preview of the UDP payload for lexicon matching. Frida
                    // byte[] elements are signed (-128..127); `& 0xff` normalizes to 0..255 and
                    // getOffset() is honored so a packet built on a subrange is read correctly.
                    var payloadStr = "";
                    try {
                        var data = packet.getData();
                        var off = packet.getOffset();
                        var cap = len < 512 ? len : 512;
                        var chars = [];
                        for (var i = 0; i < cap; i++) {
                            var b = data[off + i] & 0xff;
                            if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) chars.push(b);
                        }
                        payloadStr = String.fromCharCode.apply(null, chars);
                    } catch (e4) {}
                    if (payloadStr) console.log(C.YELLOW + "    -> Payload preview: " + payloadStr + C.RESET);
                    checkAndLog("DatagramSocket.send", dest + " " + payloadStr, null);
                } catch (e) {}
                return this.send(packet);
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook java.net.DatagramSocket.send: " + e.message + C.RESET);
        }

        // ---- Hook WebSocket Traffic via OkHttp Listener ----
        try {
            var WebSocketListener = Java.use("okhttp3.WebSocketListener");
            
            // Hook String messages (most common for C2)
            WebSocketListener.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function(ws, text) {
                console.log(C.CYAN + "\n[!] [WS-INBOUND] " + text + C.RESET);
                checkAndLog("WebSocket.onMessage", text, null);
                return this.onMessage(ws, text);
            };

            // Hook ByteString messages (binary C2)
            WebSocketListener.onMessage.overload("okhttp3.WebSocket", "okio.ByteString").implementation = function(ws, bytes) {
                var hex = bytes.hex();
                console.log(C.CYAN + "\n[!] [WS-INBOUND-BINARY] " + hex.substring(0, 64) + "..." + C.RESET);
                return this.onMessage(ws, bytes);
            };
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not hook OkHttp WebSocketListener: " + /* e.message + */ C.RESET);
        }

        console.log(C.GREEN + "[+] Hooked Java Network C2 & TLS-pinning surfaces (URL/HttpURLConnection/WebView/OkHttp/TrustManager/SSLContext/DatagramSocket)" + C.RESET);
    });
}

// ===================== MODULE: behavior-ipc (hookBehaviorIPC) =====================
// ==========================================
// ANDROID BEHAVIORAL IPC HOOKS (WHAT THE MALWARE DOES)
// ==========================================

// Java-layer behavioral hooks: SMS fraud, accessibility abuse (keylogging/auto-click),
// content resolver access to sensitive providers, command execution, package/process
// enumeration, activity/broadcast/receiver IPC, and clipboard theft. These are Java APIs
// (not hot native paths), so no isTargetCaller gating is needed; per the file convention
// (see hookJavaEvasionAPIs) Java hooks pass null as the checkAndLog trace callback.
// Each Java.use and each .overload is individually wrapped in try/catch that logs a
// one-line failure via console.log(C.YELLOW ...) - no silent empty catches.
//
// Exception: onAccessibilityEvent fires on EVERY UI event (keystrokes included), so it is
// dedup-gated via the shared ALERT_HISTORY/markSeen (keyed on event type + package) to avoid
// flooding the console and hanging the app UI - the one hot path in an otherwise cold module.
function hookBehaviorIPC() {
    if (!Java.available) {
        console.log(C.YELLOW + "[!] Java is not available. Skipping behavioral IPC hooks." + C.RESET);
        return;
    }

    Java.perform(function() {

        // Truncate long argument values for readable logs (avoids flooding on big bodies/argv).
        function preview(v) {
            var s = (v === null || v === undefined) ? "" : ("" + v);
            if (s.length > 300) s = s.substring(0, 300) + "...[TRUNCATED]";
            return s;
        }

        // Report a behavioral event and run the salient string(s) through the lexicon.
        function report(tag, label, value) {
            console.log("\n" + C.PURPLE + "[!] [" + tag + "] " + label + C.RESET);
            if (value !== null && value !== undefined && value !== "") {
                console.log(C.YELLOW + "    -> " + preview(value) + C.RESET);
                checkAndLog(tag, "" + value, null);
            }
        }

        // ---- SMS fraud: android.telephony.SmsManager ----
        try {
            var SmsManager = Java.use("android.telephony.SmsManager");

            try {
                SmsManager.sendTextMessage.overload(
                    'java.lang.String', 'java.lang.String', 'java.lang.String',
                    'android.app.PendingIntent', 'android.app.PendingIntent'
                ).implementation = function(dest, sc, body, sent, delivered) {
                    report("SMS", "SmsManager.sendTextMessage -> " + dest, body);
                    return this.sendTextMessage(dest, sc, body, sent, delivered);
                };
            } catch (e) { console.log(C.YELLOW + "[-] SmsManager.sendTextMessage hook unavailable: " + e.message + C.RESET); }

            try {
                SmsManager.sendMultipartTextMessage.overload(
                    'java.lang.String', 'java.lang.String', 'java.util.ArrayList',
                    'java.util.ArrayList', 'java.util.ArrayList'
                ).implementation = function(dest, sc, parts, sentIntents, deliveryIntents) {
                    var joined = "";
                    try {
                        if (parts !== null) {
                            var n = parts.size();
                            for (var i = 0; i < n; i++) { joined += (i ? " " : "") + parts.get(i); }
                        }
                    } catch (e) {}
                    report("SMS", "SmsManager.sendMultipartTextMessage -> " + dest, joined);
                    return this.sendMultipartTextMessage(dest, sc, parts, sentIntents, deliveryIntents);
                };
            } catch (e) { console.log(C.YELLOW + "[-] SmsManager.sendMultipartTextMessage hook unavailable: " + e.message + C.RESET); }

            try {
                SmsManager.sendDataMessage.overload(
                    'java.lang.String', 'java.lang.String', 'short', '[B',
                    'android.app.PendingIntent', 'android.app.PendingIntent'
                ).implementation = function(dest, sc, port, data, sent, delivered) {
                    var len = "unknown";
                    try { len = (data === null) ? "null" : data.length; } catch (e) {}
                    report("SMS", "SmsManager.sendDataMessage -> " + dest + " (port " + port + ")", "binary data length=" + len);
                    return this.sendDataMessage(dest, sc, port, data, sent, delivered);
                };
            } catch (e) { console.log(C.YELLOW + "[-] SmsManager.sendDataMessage hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.telephony.SmsManager: " + e.message + C.RESET); }

        // ---- Accessibility abuse: keylogging / auto-click ----
        try {
            var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

            // onAccessibilityEvent fires on EVERY UI event (extremely high frequency), so it MUST be
            // gated. We dedup on the shared ALERT_HISTORY keyed by event type + source package: the
            // first occurrence of each (type,pkg) raises a PURPLE alert; all later ones only run the
            // event text through checkAndLog (which has its own dedup) - never a per-keystroke flood.
            try {
                AccessibilityService.onAccessibilityEvent.overload('android.view.accessibility.AccessibilityEvent')
                    .implementation = function(event) {
                        try {
                            var pkg = "", txt = "", etype = "";
                            if (event !== null) {
                                try { etype = "" + event.getEventType(); } catch (e) {}
                                try { pkg = "" + event.getPackageName(); } catch (e) {}
                                try { txt = "" + event.getText(); } catch (e) {}
                            }
                            var sig = "a11yevt|" + etype + "|" + pkg;
                            if (!ALERT_HISTORY[sig]) {
                                markSeen(sig);
                                report("A11Y", "onAccessibilityEvent type=" + etype + " pkg=" + pkg, txt);
                            } else {
                                // Still lexicon-scan the text (cheap, deduped internally) without
                                // emitting another behavioral alert for this (type,pkg) pair.
                                checkAndLog("A11Y onAccessibilityEvent", txt, null);
                            }
                        } catch (e) {}
                        return this.onAccessibilityEvent(event);
                    };
            } catch (e) { console.log(C.YELLOW + "[-] AccessibilityService.onAccessibilityEvent hook unavailable: " + e.message + C.RESET); }

            try {
                AccessibilityService.dispatchGesture.overload(
                    'android.accessibilityservice.GestureDescription',
                    'android.accessibilityservice.AccessibilityService$GestureResultCallback',
                    'android.os.Handler'
                ).implementation = function(gesture, callback, handler) {
                    report("A11Y", "dispatchGesture (auto-click/auto-input)", "gesture=" + gesture);
                    return this.dispatchGesture(gesture, callback, handler);
                };
            } catch (e) { console.log(C.YELLOW + "[-] AccessibilityService.dispatchGesture hook unavailable: " + e.message + C.RESET); }

            try {
                AccessibilityService.performGlobalAction.overload('int').implementation = function(action) {
                    report("A11Y", "performGlobalAction", "action=" + action);
                    return this.performGlobalAction(action);
                };
            } catch (e) { console.log(C.YELLOW + "[-] AccessibilityService.performGlobalAction hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.accessibilityservice.AccessibilityService: " + e.message + C.RESET); }

        // ---- ContentResolver: sensitive provider access (sms/contacts/call_log) ----
        try {
            var ContentResolver = Java.use("android.content.ContentResolver");

            // Flag access to sensitive content:// authorities (SMS / contacts / call log).
            function flagSensitiveUri(where, uri) {
                var u = "";
                try { u = (uri === null) ? "" : ("" + uri); } catch (e) { u = ""; }
                var lu = u.toLowerCase();
                var sensitive = (lu.indexOf("content://sms") !== -1) ||
                                (lu.indexOf("content://mms") !== -1) ||
                                (lu.indexOf("contacts") !== -1) ||
                                (lu.indexOf("call_log") !== -1) ||
                                (lu.indexOf("calllog") !== -1);
                if (sensitive) {
                    report("CONTENT", where + " SENSITIVE provider", u);
                } else {
                    // Still run the uri through the lexicon (may hit e.g. vending/referrer tokens),
                    // but do not raise a PURPLE behavioral alert for ordinary providers.
                    checkAndLog(where, u, null);
                }
            }

            // query has multiple overloads across API levels; hook them defensively.
            try {
                ContentResolver.query.overload(
                    'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
                    '[Ljava.lang.String;', 'java.lang.String'
                ).implementation = function(uri, proj, sel, selArgs, sortOrder) {
                    flagSensitiveUri("ContentResolver.query", uri);
                    return this.query(uri, proj, sel, selArgs, sortOrder);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContentResolver.query(5-arg) hook unavailable: " + e.message + C.RESET); }

            try {
                ContentResolver.query.overload(
                    'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
                    '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal'
                ).implementation = function(uri, proj, sel, selArgs, sortOrder, sig) {
                    flagSensitiveUri("ContentResolver.query", uri);
                    return this.query(uri, proj, sel, selArgs, sortOrder, sig);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContentResolver.query(6-arg) hook unavailable: " + e.message + C.RESET); }

            try {
                ContentResolver.query.overload(
                    'android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle',
                    'android.os.CancellationSignal'
                ).implementation = function(uri, proj, queryArgs, sig) {
                    flagSensitiveUri("ContentResolver.query", uri);
                    return this.query(uri, proj, queryArgs, sig);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContentResolver.query(Bundle) hook unavailable: " + e.message + C.RESET); }

            try {
                ContentResolver.registerContentObserver.overload(
                    'android.net.Uri', 'boolean', 'android.database.ContentObserver'
                ).implementation = function(uri, notifyDescendants, observer) {
                    flagSensitiveUri("ContentResolver.registerContentObserver", uri);
                    return this.registerContentObserver(uri, notifyDescendants, observer);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContentResolver.registerContentObserver hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.content.ContentResolver: " + e.message + C.RESET); }

        // ---- Command execution: Runtime.exec (all overloads) + ProcessBuilder.start ----
        try {
            var Runtime = Java.use("java.lang.Runtime");

            function argvToStr(argv) {
                var s = "";
                try {
                    if (argv !== null) {
                        for (var i = 0; i < argv.length; i++) { s += (i ? " " : "") + argv[i]; }
                    }
                } catch (e) {}
                return s;
            }

            try {
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    report("EXEC", "Runtime.exec(String)", cmd);
                    return this.exec(cmd);
                };
            } catch (e) { console.log(C.YELLOW + "[-] Runtime.exec(String) hook unavailable: " + e.message + C.RESET); }

            try {
                Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
                    report("EXEC", "Runtime.exec(String[])", argvToStr(cmdarray));
                    return this.exec(cmdarray);
                };
            } catch (e) { console.log(C.YELLOW + "[-] Runtime.exec(String[]) hook unavailable: " + e.message + C.RESET); }

            try {
                Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(cmd, envp) {
                    report("EXEC", "Runtime.exec(String, envp)", cmd);
                    return this.exec(cmd, envp);
                };
            } catch (e) { console.log(C.YELLOW + "[-] Runtime.exec(String,envp) hook unavailable: " + e.message + C.RESET); }

            try {
                Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function(cmdarray, envp) {
                    report("EXEC", "Runtime.exec(String[], envp)", argvToStr(cmdarray));
                    return this.exec(cmdarray, envp);
                };
            } catch (e) { console.log(C.YELLOW + "[-] Runtime.exec(String[],envp) hook unavailable: " + e.message + C.RESET); }

            try {
                Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmd, envp, dir) {
                    report("EXEC", "Runtime.exec(String, envp, dir)", cmd);
                    return this.exec(cmd, envp, dir);
                };
            } catch (e) { console.log(C.YELLOW + "[-] Runtime.exec(String,envp,dir) hook unavailable: " + e.message + C.RESET); }

            try {
                Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File').implementation = function(cmdarray, envp, dir) {
                    report("EXEC", "Runtime.exec(String[], envp, dir)", argvToStr(cmdarray));
                    return this.exec(cmdarray, envp, dir);
                };
            } catch (e) { console.log(C.YELLOW + "[-] Runtime.exec(String[],envp,dir) hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook java.lang.Runtime.exec: " + e.message + C.RESET); }

        try {
            var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
            try {
                ProcessBuilder.start.overload().implementation = function() {
                    var cmd = "";
                    try {
                        var list = this.command();
                        if (list !== null) {
                            var n = list.size();
                            for (var i = 0; i < n; i++) { cmd += (i ? " " : "") + list.get(i); }
                        }
                    } catch (e) {}
                    report("EXEC", "ProcessBuilder.start", cmd);
                    return this.start();
                };
            } catch (e) { console.log(C.YELLOW + "[-] ProcessBuilder.start hook unavailable: " + e.message + C.RESET); }
        } catch (e) { console.log(C.YELLOW + "[-] Could not hook java.lang.ProcessBuilder: " + e.message + C.RESET); }

        // ---- Package enumeration: ApplicationPackageManager ----
        try {
            var PM = Java.use("android.app.ApplicationPackageManager");

            ["getInstalledPackages", "getInstalledApplications"].forEach(function(m) {
                try {
                    PM[m].overload('int').implementation = function(flags) {
                        report("PKG", "PackageManager." + m + " (device app enumeration)", "flags=" + flags);
                        return this[m](flags);
                    };
                } catch (e) { console.log(C.YELLOW + "[-] PackageManager." + m + " hook unavailable: " + e.message + C.RESET); }
            });

            try {
                PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
                    report("PKG", "PackageManager.getPackageInfo", pkg);
                    return this.getPackageInfo(pkg, flags);
                };
            } catch (e) { console.log(C.YELLOW + "[-] PackageManager.getPackageInfo(String,int) hook unavailable: " + e.message + C.RESET); }

            try {
                PM.getInstallerPackageName.overload('java.lang.String').implementation = function(pkg) {
                    if (ACTIVE_BYPASS) {
                        console.log(C.RED + "    -> [BYPASS] Spoofing installer as Google Play Store (com.android.vending) for: " + pkg + C.RESET);
                        return "com.android.vending";
                    }
                    var v = this.getInstallerPackageName(pkg);
                    report("PKG", "PackageManager.getInstallerPackageName(" + pkg + ")", "" + v);
                    return v;
                };
            } catch (e) { console.log(C.YELLOW + "[-] PackageManager.getInstallerPackageName hook unavailable: " + e.message + C.RESET); }

            try {
                PM.getInstallSourceInfo.overload('java.lang.String').implementation = function(pkg) {
                    var v = this.getInstallSourceInfo(pkg);
                    var inst = "";
                    try { inst = "" + v.getInstallingPackageName(); } catch (e) {}
                    report("PKG", "PackageManager.getInstallSourceInfo(" + pkg + ")", "installer=" + inst);
                    return v;
                };
            } catch (e) { console.log(C.YELLOW + "[-] PackageManager.getInstallSourceInfo hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.app.ApplicationPackageManager: " + e.message + C.RESET); }

        // ---- Process/service enumeration: ActivityManager ----
        try {
            var AM = Java.use("android.app.ActivityManager");
            try {
                AM.getRunningAppProcesses.overload().implementation = function() {
                    report("PROC", "ActivityManager.getRunningAppProcesses (running process enumeration)", null);
                    return this.getRunningAppProcesses();
                };
            } catch (e) { console.log(C.YELLOW + "[-] ActivityManager.getRunningAppProcesses hook unavailable: " + e.message + C.RESET); }

            try {
                AM.getRunningServices.overload('int').implementation = function(maxNum) {
                    report("PROC", "ActivityManager.getRunningServices (running service enumeration)", "maxNum=" + maxNum);
                    return this.getRunningServices(maxNum);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ActivityManager.getRunningServices hook unavailable: " + e.message + C.RESET); }
        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.app.ActivityManager: " + e.message + C.RESET); }

        // ---- IPC: ContextWrapper startActivity / sendBroadcast / registerReceiver ----
        try {
            var ContextWrapper = Java.use("android.content.ContextWrapper");

            function intentStr(intent) {
                var s = "";
                try {
                    if (intent !== null) {
                        var act = "";
                        try { act = "" + intent.getAction(); } catch (e) {}
                        var data = "";
                        try { data = "" + intent.getDataString(); } catch (e) {}
                        var comp = "";
                        try { var c = intent.getComponent(); if (c !== null) comp = "" + c.flattenToString(); } catch (e) {}
                        s = "action=" + act + " data=" + data + (comp ? " comp=" + comp : "");
                    }
                } catch (e) {}
                return s;
            }

            try {
                ContextWrapper.startActivity.overload('android.content.Intent').implementation = function(intent) {
                    report("IPC", "ContextWrapper.startActivity", intentStr(intent));
                    return this.startActivity(intent);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContextWrapper.startActivity(Intent) hook unavailable: " + e.message + C.RESET); }

            try {
                ContextWrapper.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function(intent, opts) {
                    report("IPC", "ContextWrapper.startActivity", intentStr(intent));
                    return this.startActivity(intent, opts);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContextWrapper.startActivity(Intent,Bundle) hook unavailable: " + e.message + C.RESET); }

            try {
                ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
                    report("IPC", "ContextWrapper.sendBroadcast", intentStr(intent));
                    return this.sendBroadcast(intent);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContextWrapper.sendBroadcast(Intent) hook unavailable: " + e.message + C.RESET); }

            try {
                ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function(intent, perm) {
                    report("IPC", "ContextWrapper.sendBroadcast", intentStr(intent));
                    return this.sendBroadcast(intent, perm);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContextWrapper.sendBroadcast(Intent,String) hook unavailable: " + e.message + C.RESET); }

            try {
                ContextWrapper.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter').implementation = function(rcv, filter) {
                    var act = "";
                    try { if (filter !== null && filter.countActions() > 0) act = "" + filter.getAction(0); } catch (e) {}
                    report("IPC", "ContextWrapper.registerReceiver", "firstAction=" + act);
                    return this.registerReceiver(rcv, filter);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContextWrapper.registerReceiver(2-arg) hook unavailable: " + e.message + C.RESET); }

            try {
                ContextWrapper.registerReceiver.overload('android.content.BroadcastReceiver', 'android.content.IntentFilter', 'java.lang.String', 'android.os.Handler').implementation = function(rcv, filter, perm, handler) {
                    var act = "";
                    try { if (filter !== null && filter.countActions() > 0) act = "" + filter.getAction(0); } catch (e) {}
                    report("IPC", "ContextWrapper.registerReceiver", "firstAction=" + act);
                    return this.registerReceiver(rcv, filter, perm, handler);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ContextWrapper.registerReceiver(4-arg) hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.content.ContextWrapper: " + e.message + C.RESET); }

        // ---- Clipboard theft: ClipboardManager get/set PrimaryClip ----
        try {
            var Clipboard = Java.use("android.content.ClipboardManager");

            function clipStr(clip) {
                // Clipboard content is attacker-controlled and may be large; bound how much we
                // materialize across the JNI bridge (each item is truncated, and we stop early once
                // the accumulator is large enough for triage).
                var CLIP_CAP = 512;
                var s = "";
                try {
                    if (clip !== null) {
                        var n = clip.getItemCount();
                        for (var i = 0; i < n && s.length < CLIP_CAP; i++) {
                            try {
                                var item = clip.getItemAt(i);
                                var t = item.getText();
                                if (t !== null) {
                                    var chunk = "" + t;
                                    if (chunk.length > CLIP_CAP) chunk = chunk.substring(0, CLIP_CAP);
                                    s += (i ? " | " : "") + chunk;
                                }
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
                return s;
            }

            try {
                Clipboard.getPrimaryClip.overload().implementation = function() {
                    var clip = this.getPrimaryClip();
                    report("CLIP", "ClipboardManager.getPrimaryClip (clipboard read/theft)", clipStr(clip));
                    return clip;
                };
            } catch (e) { console.log(C.YELLOW + "[-] ClipboardManager.getPrimaryClip hook unavailable: " + e.message + C.RESET); }

            try {
                Clipboard.setPrimaryClip.overload('android.content.ClipData').implementation = function(clip) {
                    report("CLIP", "ClipboardManager.setPrimaryClip (clipboard write/hijack)", clipStr(clip));
                    return this.setPrimaryClip(clip);
                };
            } catch (e) { console.log(C.YELLOW + "[-] ClipboardManager.setPrimaryClip hook unavailable: " + e.message + C.RESET); }

        } catch (e) { console.log(C.YELLOW + "[-] Could not hook android.content.ClipboardManager: " + e.message + C.RESET); }

        console.log(C.GREEN + "[+] Hooked Behavioral IPC (SMS, A11Y, ContentResolver, exec, PackageManager, ActivityManager, IPC, Clipboard)" + C.RESET);
    });
}

// ===================== MODULE: java-antidebug-state (hookJavaStateAndDebug) =====================
// ==========================================
// JAVA ANTI-DEBUG + PERSISTENT STATE + NATIVE SQLITE
// ==========================================

// Java anti-debug (Debug/VMDebug), persistent config/C2 state (SharedPreferences),
// and native libsqlite.so hooks (stolen-data DB path, prepared SQL, and the actual
// values bound behind '?' placeholders). Under ACTIVE_BYPASS the debugger-connected
// checks are forced to report "no debugger" to defeat the anti-analysis gate.
// Reuses the shared helpers/globals already defined in this file (C, ACTIVE_BYPASS,
// checkAndLog, getExportSafe, readStrSafe, getNativeBacktrace, isTargetCaller).
function hookJavaStateAndDebug() {
    hookSqliteNative();

    if (!Java.available) {
        console.log(C.YELLOW + "[!] Java is not available. Skipping anti-debug/state hooks." + C.RESET);
        return;
    }

    Java.perform(function () {
        // ---- android.os.Debug: isDebuggerConnected / waitingForDebugger ----
        // Both are static and take no args. Inside a Frida .implementation override,
        // this.<method>() dispatches to the ORIGINAL (un-hooked) impl - no recursion.
        // Under ACTIVE_BYPASS we return false so the sample believes no debugger/JDWP
        // is attached and proceeds with real behavior.
        try {
            var Debug = Java.use("android.os.Debug");
            try {
                Debug.isDebuggerConnected.implementation = function () {
                    var real = this.isDebuggerConnected();
                    console.log(C.PURPLE + "[!] [ANTI-DEBUG] Debug.isDebuggerConnected() -> " + real + C.RESET);
                    if (ACTIVE_BYPASS) {
                        console.log(C.RED + "    -> [BYPASS] Forcing Debug.isDebuggerConnected() = false" + C.RESET);
                        return false;
                    }
                    return real;
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook Debug.isDebuggerConnected: " + e.message + C.RESET);
            }
            try {
                Debug.waitingForDebugger.implementation = function () {
                    var real = this.waitingForDebugger();
                    console.log(C.PURPLE + "[!] [ANTI-DEBUG] Debug.waitingForDebugger() -> " + real + C.RESET);
                    if (ACTIVE_BYPASS) {
                        console.log(C.RED + "    -> [BYPASS] Forcing Debug.waitingForDebugger() = false" + C.RESET);
                        return false;
                    }
                    return real;
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook Debug.waitingForDebugger: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use android.os.Debug: " + e.message + C.RESET);
        }

        // ---- dalvik.system.VMDebug.isDebuggerConnected (static, no args) ----
        // This is the native method android.os.Debug.isDebuggerConnected() delegates to;
        // hooking it catches callers that reach the runtime directly. Individually guarded
        // in case a given ART build does not expose it.
        try {
            var VMDebug = Java.use("dalvik.system.VMDebug");
            try {
                VMDebug.isDebuggerConnected.implementation = function () {
                    var real = this.isDebuggerConnected();
                    console.log(C.PURPLE + "[!] [ANTI-DEBUG] VMDebug.isDebuggerConnected() -> " + real + C.RESET);
                    if (ACTIVE_BYPASS) {
                        console.log(C.RED + "    -> [BYPASS] Forcing VMDebug.isDebuggerConnected() = false" + C.RESET);
                        return false;
                    }
                    return real;
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook VMDebug.isDebuggerConnected: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use dalvik.system.VMDebug: " + e.message + C.RESET);
        }

        // ---- android.app.SharedPreferencesImpl: getString / getBoolean (reads) ----
        // Malware persists C2 endpoints, install flags, first-run markers, kill-switches
        // here. Log key + returned value and run both through checkAndLog for salient tokens.

        // getString is called very frequently for routine config reads, so log at most once per
        // (kind|key) and truncate the value - otherwise this floods the console with full,
        // possibly-large stored blobs. checkAndLog (below) still runs per-call for detection.
        function prefsLog(kind, key, val) {
            var sig = "prefs|" + kind + "|" + key;
            if (ALERT_HISTORY[sig]) return;
            markSeen(sig);
            var v = "" + val;
            if (v.length > 300) v = v.substring(0, 300) + "...[truncated]";
            console.log(C.PURPLE + "[!] [PREFS] " + kind + "(" + key + ") -> " + v + C.RESET);
        }

        try {
            var SPImpl = Java.use("android.app.SharedPreferencesImpl");
            try {
                SPImpl.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defVal) {
                    var val = this.getString(key, defVal);
                    prefsLog("getString", "" + key, val);
                    checkAndLog("SharedPreferences.getString.key", "" + key, null);
                    if (val !== null) checkAndLog("SharedPreferences.getString.value", "" + val, null);
                    return val;
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook SharedPreferencesImpl.getString: " + e.message + C.RESET);
            }
            try {
                SPImpl.getBoolean.overload('java.lang.String', 'boolean').implementation = function (key, defVal) {
                    var val = this.getBoolean(key, defVal);
                    prefsLog("getBoolean", "" + key, val);
                    checkAndLog("SharedPreferences.getBoolean.key", "" + key, null);
                    return val;
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook SharedPreferencesImpl.getBoolean: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use android.app.SharedPreferencesImpl: " + e.message + C.RESET);
        }

        // ---- android.app.SharedPreferencesImpl$EditorImpl.putString (writes) ----
        // Captures newly-stored config/flags (e.g. saved C2, campaign IDs) as they are written.
        try {
            var EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            try {
                EditorImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
                    prefsLog("putString", "" + key, value);
                    checkAndLog("SharedPreferences.putString.key", "" + key, null);
                    if (value !== null) checkAndLog("SharedPreferences.putString.value", "" + value, null);
                    return this.putString(key, value);
                };
            } catch (e) {
                console.log(C.YELLOW + "[-] Could not hook EditorImpl.putString: " + e.message + C.RESET);
            }
        } catch (e) {
            console.log(C.YELLOW + "[-] Could not use SharedPreferencesImpl$EditorImpl: " + e.message + C.RESET);
        }

        console.log(C.GREEN + "[+] Hooked Java anti-debug (Debug/VMDebug) and persistent state (SharedPreferences)" + C.RESET);
    });
}

// Upper bound on how many bytes we ever read from a caller-supplied SQLite length. A
// hostile / bogus nByte (huge or negative-cast) must not trigger a pathological or OOB
// read; readStrSafe additionally catches faults, so at worst we truncate over-long text.
var SQLITE_MAX_TEXT = 262144;

// Native libsqlite.so hooks. Detection-only (never spoofs): sqlite3_open_v2 exposes the
// on-disk DB path (stolen-data / staging DBs), sqlite3_prepare_v2 exposes the SQL text
// (including '?' placeholders), and sqlite3_bind_text exposes the ACTUAL values substituted
// behind those placeholders (exfiltrated fields). Frequency gating: SQLite calls are only
// moderately hot and are further narrowed by isTargetCaller(this.returnAddress) module
// gating; bind_text additionally only surfaces via checkAndLog (which prints only on a
// TARGET_STRINGS match), so it never floods on ordinary parameter binds.
function hookSqliteNative() {
    // sqlite3_open_v2(filename, ppDb, flags, zVfs): path is arg0 (NUL-terminated).
    var openPtr = getExportSafe("libsqlite.so", "sqlite3_open_v2");
    if (openPtr) {
        try {
            Interceptor.attach(openPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var path = readStrSafe(args[0]);
                    if (!path) return;
                    var ctx = this.context; // capture: trace closures are called bare by checkAndLog
                    console.log(C.PURPLE + "[!] [SQLITE] sqlite3_open_v2 -> " + path + C.RESET);
                    checkAndLog("sqlite3_open_v2", path, function () { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked SQLite: sqlite3_open_v2" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook sqlite3_open_v2: " + e.message + C.RESET);
        }
    }

    // sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail): SQL text is arg1.
    // nByte (arg2) may be -1 (NUL-terminated) or an explicit byte length; when it is a sane
    // positive value use it, otherwise fall back to a NUL-terminated read. readUtf8String
    // still stops at the first embedded NUL within the given size.
    var prepPtr = getExportSafe("libsqlite.so", "sqlite3_prepare_v2");
    if (prepPtr) {
        try {
            Interceptor.attach(prepPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var nByte = -1;
                    try { nByte = args[2].toInt32(); } catch (e) {}
                    var sql = (nByte > 0 && nByte <= SQLITE_MAX_TEXT)
                        ? readStrSafe(args[1], nByte)
                        : readStrSafe(args[1]);
                    if (!sql) return;
                    var ctx = this.context;
                    console.log(C.CYAN + "[!] [SQLITE] sqlite3_prepare_v2 -> " + sql + C.RESET);
                    checkAndLog("sqlite3_prepare_v2", sql, function () { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked SQLite: sqlite3_prepare_v2" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook sqlite3_prepare_v2: " + e.message + C.RESET);
        }
    }

    // sqlite3_bind_text(stmt, index, value, nBytes, destructor): value is arg2, length arg3.
    // This reveals the concrete data substituted for '?' placeholders in prepared statements -
    // i.e. the actual field values being written to / queried from the stolen-data DB.
    var bindPtr = getExportSafe("libsqlite.so", "sqlite3_bind_text");
    if (bindPtr) {
        try {
            Interceptor.attach(bindPtr, {
                onEnter: function (args) {
                    if (!isTargetCaller(this.returnAddress)) return;
                    var nBytes = -1;
                    try { nBytes = args[3].toInt32(); } catch (e) {}
                    var val = (nBytes > 0 && nBytes <= SQLITE_MAX_TEXT)
                        ? readStrSafe(args[2], nBytes)
                        : readStrSafe(args[2]);
                    // Content gating: skip empty binds entirely; checkAndLog only surfaces
                    // (and dedups) values that match the lexicon, so routine binds stay silent.
                    if (!val) return;
                    var ctx = this.context;
                    checkAndLog("sqlite3_bind_text", val, function () { return getNativeBacktrace(ctx); });
                }
            });
            console.log(C.GREEN + "[+] Hooked SQLite: sqlite3_bind_text" + C.RESET);
        } catch (e) {
            console.log(C.RED + "[-] Failed to hook sqlite3_bind_text: " + e.message + C.RESET);
        }
    }
}

// ===================== MODULE: unity-il2cpp (hookUnityIL2CPP) =====================
// ==========================================
// UNITY IL2CPP ENGINE HOOKS (C# DECRYPTION & STRINGS)
// ==========================================

// Helper to safely read a C# byte[] inside IL2CPP memory
function readIl2CppByteArray(arrayPtr) {
    if (!arrayPtr || arrayPtr.isNull()) return null;
    var pSize = Process.pointerSize;
    var lengthOffset = (pSize === 8) ? 0x18 : 0x0C;
    var dataOffset = (pSize === 8) ? 0x20 : 0x10;
    
    try {
        var len = arrayPtr.add(lengthOffset).readU32();
        if (len > 0 && len < 1024 * 1024 * 10) { 
            return arrayPtr.add(dataOffset).readByteArray(len);
        }
    } catch(e) {}
    return null;
}

// Robust API Resolver: Checks exports first, falls back to internal symbols
function getIl2CppApi(name) {
    var ptr = Module.findExportByName("libil2cpp.so", name);
    if (ptr) return ptr;
    
    try {
        var symbols = Process.getModuleByName("libil2cpp.so").enumerateSymbols();
        for (var i = 0; i < symbols.length; i++) {
            if (symbols[i].name === name) return symbols[i].address;
        }
    } catch (e) {}
    return null;
}

// IL2CPP Dynamic Method Resolver
function hookIl2cppMethod(namespaceName, className, methodName, argCount, callbacks) {
    try {
        var p_domainGet = getIl2CppApi("il2cpp_domain_get");
        var p_domainGetAssemblies = getIl2CppApi("il2cpp_domain_get_assemblies");
        var p_assemblyGetImage = getIl2CppApi("il2cpp_assembly_get_image");
        var p_classFromName = getIl2CppApi("il2cpp_class_from_name");
        var p_classGetMethodFromName = getIl2CppApi("il2cpp_class_get_method_from_name");

        if (!p_domainGet || !p_domainGetAssemblies || !p_assemblyGetImage || !p_classFromName || !p_classGetMethodFromName) {
            throw new Error("IL2CPP APIs are completely stripped from this binary.");
        }

        var domainGet = new NativeFunction(p_domainGet, 'pointer', []);
        var domainGetAssemblies = new NativeFunction(p_domainGetAssemblies, 'pointer', ['pointer', 'pointer']);
        var assemblyGetImage = new NativeFunction(p_assemblyGetImage, 'pointer', ['pointer']);
        var classFromName = new NativeFunction(p_classFromName, 'pointer', ['pointer', 'pointer', 'pointer']);
        var classGetMethodFromName = new NativeFunction(p_classGetMethodFromName, 'pointer', ['pointer', 'pointer', 'int']);

        var domain = domainGet();
        var sizePtr = Memory.alloc(Process.pointerSize);
        var assemblies = domainGetAssemblies(domain, sizePtr);
        var count = sizePtr.readU32();

        for (var i = 0; i < count; i++) {
            var assembly = assemblies.add(i * Process.pointerSize).readPointer();
            var image = assemblyGetImage(assembly);
            
            var nsPtr = Memory.allocUtf8String(namespaceName);
            var clsPtr = Memory.allocUtf8String(className);
            var klass = classFromName(image, nsPtr, clsPtr);
            
            if (!klass.isNull()) {
                var methPtr = Memory.allocUtf8String(methodName);
                var method = classGetMethodFromName(klass, methPtr, argCount);
                if (!method.isNull()) {
                    var methodPointer = method.readPointer(); 
                    if (!methodPointer.isNull()) {
                        Interceptor.attach(methodPointer, callbacks);
                        console.log(C.GREEN + "[+] Hooked C# Method: " + namespaceName + "." + className + "." + methodName + C.RESET);
                        return true;
                    }
                }
            }
        }
        console.log(C.YELLOW + "[-] Method not found in IL2CPP memory: " + className + "." + methodName + C.RESET);
    } catch (e) {
        console.log(C.YELLOW + "[-] Could not resolve IL2CPP method " + className + "." + methodName + ": " + e.message + C.RESET);
    }
    return false;
}

// Manual Offset Hooker (Use this if the binary is completely stripped)
function hookIl2cppByOffset(className, methodName, offset, callbacks) {
    try {
        var il2cppBase = Module.getBaseAddress("libil2cpp.so");
        var targetAddr = il2cppBase.add(offset);
        Interceptor.attach(targetAddr, callbacks);
        console.log(C.GREEN + "[+] Hooked C# Method (by offset): " + className + "." + methodName + " @ " + targetAddr + C.RESET);
    } catch (e) {
        console.log(C.RED + "[-] Failed to hook offset for " + className + "." + methodName + ": " + e.message + C.RESET);
    }
}

function hookUnityIL2CPP() {
    var il2cpp = Process.getModuleByName("libil2cpp.so");
    if (!il2cpp) {
        console.log(C.YELLOW + "[-] libil2cpp.so not loaded. Not a Unity IL2CPP game." + C.RESET);
        return;
    }
    console.log(C.GREEN + "[+] Unity IL2CPP Engine detected. Injecting C# decloaking hooks..." + C.RESET);

    // If dynamic resolution fails, you will need to run Il2CppDumper and replace '0x000000'
    // with the actual offsets from your dummyDlls/script.json
    var STRIPPED_MODE = false; 
    var OFFSETS = {
        Convert_FromBase64String: 0x000000, 
        Aes_set_Key: 0x000000,
        Aes_set_IV: 0x000000,
        TransformFinalBlock: 0x000000
    };

    // -------------------------------------------------------------------------
    // 1. C# BASE64 DECODING
    // -------------------------------------------------------------------------
    var b64Callbacks = {
        onEnter: function(args) {
            var pSize = Process.pointerSize;
            var strOffset = (pSize === 8) ? 0x14 : 0x0C;
            try { this.b64Str = args[0].add(strOffset).readUtf16String(); } 
            catch(e) { this.b64Str = "[Error reading IL2CPP String]"; }
        },
        onLeave: function(retval) {
            if (this.b64Str && this.b64Str.length > 20) {
                console.log("\n" + C.PURPLE + "[!] [UNITY CRYPTO] System.Convert.FromBase64String" + C.RESET);
                console.log(C.YELLOW + "    -> Input Base64: " + this.b64Str.substring(0, 150) + "..." + C.RESET);
                var rawBytes = readIl2CppByteArray(retval);
                if (rawBytes) {
                    var mem = Memory.alloc(rawBytes.byteLength).writeByteArray(rawBytes);
                    console.log(C.YELLOW + "    -> Output Bytes: " + hexPreview(mem, 32) + C.RESET);
                }
            }
        }
    };

    if (STRIPPED_MODE) hookIl2cppByOffset("System.Convert", "FromBase64String", OFFSETS.Convert_FromBase64String, b64Callbacks);
    else hookIl2cppMethod("System", "Convert", "FromBase64String", 1, b64Callbacks);

    // -------------------------------------------------------------------------
    // 2. C# AES KEY & IV STEALERS
    // -------------------------------------------------------------------------
    var keyCallbacks = {
        onEnter: function(args) {
            var keyBytes = readIl2CppByteArray(args[1]);
            if (keyBytes) {
                var mem = Memory.alloc(keyBytes.byteLength).writeByteArray(keyBytes);
                console.log("\n" + C.RED + "[!] [UNITY CRYPTO] AES Key Configured!" + C.RESET);
                console.log(C.YELLOW + "    -> Key (Hex): " + hexPreview(mem, 64) + C.RESET);
            }
        }
    };
    
    var ivCallbacks = {
        onEnter: function(args) {
            var ivBytes = readIl2CppByteArray(args[1]);
            if (ivBytes) {
                var mem = Memory.alloc(ivBytes.byteLength).writeByteArray(ivBytes);
                console.log("\n" + C.RED + "[!] [UNITY CRYPTO] AES IV Configured!" + C.RESET);
                console.log(C.YELLOW + "    -> IV (Hex):  " + hexPreview(mem, 64) + C.RESET);
            }
        }
    };

    if (STRIPPED_MODE) {
        hookIl2cppByOffset("SymmetricAlgorithm", "set_Key", OFFSETS.Aes_set_Key, keyCallbacks);
        hookIl2cppByOffset("SymmetricAlgorithm", "set_IV", OFFSETS.Aes_set_IV, ivCallbacks);
    } else {
        hookIl2cppMethod("System.Security.Cryptography", "SymmetricAlgorithm", "set_Key", 1, keyCallbacks);
        hookIl2cppMethod("System.Security.Cryptography", "SymmetricAlgorithm", "set_IV", 1, ivCallbacks);
    }

    // -------------------------------------------------------------------------
    // 3. C# BLOCK CIPHER DECRYPTION (RijndaelManagedTransform)
    // -------------------------------------------------------------------------
    var transformCallbacks = {
        onEnter: function(args) {
            this.inCount = args[3].toInt32();
            this.inBytes = readIl2CppByteArray(args[1]);
        },
        onLeave: function(retval) {
            console.log("\n" + C.PURPLE + "[!] [UNITY CRYPTO] AES TransformFinalBlock Executed" + C.RESET);
            if (this.inBytes) {
                var inMem = Memory.alloc(this.inBytes.byteLength).writeByteArray(this.inBytes);
                console.log(C.YELLOW + "    -> Input Ciphertext: " + hexPreview(inMem, 32) + C.RESET);
            }
            var outBytes = readIl2CppByteArray(retval);
            if (outBytes) {
                var outMem = Memory.alloc(outBytes.byteLength).writeByteArray(outBytes);
                var plainStr = "";
                var u8 = new Uint8Array(outBytes);
                for(var i = 0; i < u8.length; i++) {
                    if (u8[i] >= 32 && u8[i] <= 126) plainStr += String.fromCharCode(u8[i]);
                }
                if (plainStr.length > 5) {
                    console.log(C.GREEN + "    -> Output Plaintext ASCII: " + plainStr + C.RESET);
                } else {
                    console.log(C.GREEN + "    -> Output Plaintext Hex: " + hexPreview(outMem, 64) + C.RESET);
                }
            }
        }
    };

    if (STRIPPED_MODE) hookIl2cppByOffset("RijndaelManagedTransform", "TransformFinalBlock", OFFSETS.TransformFinalBlock, transformCallbacks);
    else hookIl2cppMethod("System.Security.Cryptography", "RijndaelManagedTransform", "TransformFinalBlock", 3, transformCallbacks);
}

// ==========================================
// INITIALIZER
// ==========================================

setImmediate(function() {
    console.log(C.CYAN + "=========================================" + C.RESET);
    console.log(C.CYAN + "[*] Sigma Decloaker V28 " + C.RESET);
    console.log(C.CYAN + "=========================================" + C.RESET);
    console.log((ACTIVE_BYPASS
        ? C.RED + "[*] ACTIVE_BYPASS: ENABLED - the sample's behavior is being MUTATED."
        : C.GREEN + "[*] ACTIVE_BYPASS: disabled (observe-only). Enable via the setbypass RPC.") + C.RESET);
   
    if (TARGET_MODULES.length > 0) {
        for (var i = 0; i < TARGET_MODULES.length; i++) {
            if (Process.findModuleByName(TARGET_MODULES[i]) === null) {
                console.log(C.YELLOW + "[!] Warning: Target '" + TARGET_MODULES[i] + "' is not currently mapped in memory." + C.RESET);
            } else {
                console.log(C.GREEN + "[+] Target '" + TARGET_MODULES[i] + "' is loaded and actively monitored." + C.RESET);
            }
        }
    }

    // Use an interval to catch libil2cpp.so if the game loads it slightly after launch
    var unityWait = setInterval(function() {
        if (Process.findModuleByName("libil2cpp.so")) {
            clearInterval(unityWait);
            hookUnityIL2CPP();
        }
    }, 500);

    safeAttachIO("libc.so", "open", 0);
    safeAttachIO("libc.so", "openat", 1); 
    safeAttachIO("libc.so", "fopen", 0);
    safeAttachIO("libc.so", "access", 0); 
    safeAttachIO("libc.so", "faccessat", 1);
    safeAttachIO("libc.so", "__system_property_get", 0);

    // File-existence probing: the stat/lstat/statx family (common root/emulator existence
    // checks; Java File.exists() lowers to these, not access). Path arg is 0, *at variants 1.
    safeAttachIO("libc.so", "stat", 0);
    safeAttachIO("libc.so", "lstat", 0);
    safeAttachIO("libc.so", "stat64", 0);
    safeAttachIO("libc.so", "lstat64", 0);
    safeAttachIO("libc.so", "newfstatat", 1);
    safeAttachIO("libc.so", "statx", 1);

    hookDeepExecution();
    hookRawSyscalls();       // direct syscall() evasion of the libc-export hooks above
    // BREAKS: hookLibraryLoading();    // dlopen/dlsym/android_dlopen_ext/getenv
    // BREAKS WITH SYSTEM LIBS: hookJavaNativeLoaders();

    hookSystemProperties();
    hookNativeFileIO();

    hookJavaDCL();
    hookJavaEvasionAPIs();   // Settings.Secure / Telephony / Sensor emulator checks
    hookNetworkTraffic();
    // BREAKS: hookStringsNative();
    hookLibart();
    hookJNIEnv(); // Intercept specific JNIEnv structures

    // ---- extended coverage (JNI/ART, crypto, memory, network, behavioral IPC, anti-debug) ----
    hookJNIEnvExtended(); // extended JNIEnv vtable coverage (string/byte regions, Call* families, DefineClass, exceptions)
    hookArtDexLoaders();
    hookFileContent();
    hookFsRecon();
    hookCryptoJava();
    hookCryptoNative();
    hookMemoryUnpacking();  // mprotect/mmap/memfd_create/munmap - memory-unpacking primitives
    hookReflection();
    hookAntiDebugNative();
    hookPropertyModern();
    hookNetworkC2Native();
    hookNetworkC2Java();
    hookBehaviorIPC();   // Android behavioral IPC: SMS/A11Y/ContentResolver/exec/PackageManager/ActivityManager/IPC/Clipboard
    // BREAKS: hookJavaStateAndDebug();
});