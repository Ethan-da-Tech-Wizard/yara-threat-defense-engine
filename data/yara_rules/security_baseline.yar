/*
   TWU LLC Sovereign Threat Defense - Baseline YARA Rules
   Scope: Suspicious reverse shells, piped download-and-exec, webshells, miners.
   Offline, deterministic, zero telemetry.
*/

rule Linux_Reverse_Shell {
    meta:
        description = "Detects interactive shell redirection over TCP or named pipes"
        author = "TWU Security"
        severity = "HIGH"
    strings:
        $dev_tcp = "/dev/tcp/" ascii
        $sh_redirect = "sh -i >& /dev/tcp/" ascii
        $bash_redirect = "bash -i >& /dev/tcp/" ascii
        $nc_e = /nc(\.traditional|\.openbsd)?\s+(-[a-zA-Z]*e[a-zA-Z]*\s+)?(\/bin\/)?(ba)?sh/ ascii
        $py_rev = /python[23]?\s+-c\s+['"].{0,100}import\s+(socket|subprocess|pty).{0,100}socket\.connect/ ascii
        $perl_rev = /perl\s+-e\s+['"].{0,100}use\s+Socket.{0,100}connect\(.{0,100}exec\(["']\/bin\/sh/ ascii
    condition:
        any of them
}

rule Suspicious_Piped_Execution {
    meta:
        description = "Detects curl/wget piping straight into a shell or base64 eval execution"
        author = "TWU Security"
        severity = "MEDIUM"
    strings:
        $curl_bash = /curl\s+[^|\n]{1,120}\|\s*(ba)?sh/ ascii
        $wget_bash = /wget\s+[^|\n]{1,120}\|\s*(ba)?sh/ ascii
        $b64_eval = /echo\s+[A-Za-z0-9+\/=]{20,200}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh/ ascii
    condition:
        any of them
}

rule Cryptominer_Artifacts {
    meta:
        description = "Detects common crypto-jacking and mining pool connection strings"
        author = "TWU Security"
        severity = "HIGH"
    strings:
        $stratum1 = "stratum+tcp://" ascii nocase
        $stratum2 = "stratum+ssl://" ascii nocase
        $miner1 = "xmrig" ascii nocase
        $miner2 = "cryptonight" ascii nocase
        $miner3 = "minergate" ascii nocase
    condition:
        any of them
}

rule Webshell_Command_Execution {
    meta:
        description = "Detects raw command execution webshell stubs"
        author = "TWU Security"
        severity = "HIGH"
    strings:
        $php_eval = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[/ ascii nocase
        $php_sys = /system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[/ ascii nocase
        $php_exec = /exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[/ ascii nocase
        $php_passthru = /passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[/ ascii nocase
    condition:
        any of them
}
