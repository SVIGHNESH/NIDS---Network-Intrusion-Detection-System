/*
  NIDS Custom YARA Rules
  Author  : Vighnesh NIDS
  Version : 1.0
  Purpose : Signature-based detection for common network attack patterns
  Usage   : yara nids_rules.yar <pcap_payload_dump>
            or loaded via yara-python in your packet handler
*/

// ─────────────────────────────────────────────────────────────
// SECTION 1 — WEB ATTACKS
// ─────────────────────────────────────────────────────────────

rule SQL_Injection_Classic {
    meta:
        id          = "WEB-001"
        severity    = "high"
        description = "Classic SQL injection patterns in HTTP payload"
        author      = "Vighnesh"

    strings:
        $s1 = "' OR '1'='1"        ascii nocase
        $s2 = "' OR 1=1--"         ascii nocase
        $s3 = "UNION SELECT"        ascii nocase
        $s4 = "DROP TABLE"          ascii nocase
        $s5 = "INSERT INTO"         ascii nocase
        $s6 = "; exec("             ascii nocase
        $s7 = "xp_cmdshell"         ascii nocase
        $s8 = "INFORMATION_SCHEMA"  ascii nocase
        $hex1 = { 27 20 4F 52 20 31 3D 31 }   // ' OR 1=1 in hex

    condition:
        any of them
}

rule SQL_Injection_Blind {
    meta:
        id          = "WEB-002"
        severity    = "high"
        description = "Blind SQL injection timing / boolean patterns"

    strings:
        $t1 = "SLEEP("         ascii nocase
        $t2 = "WAITFOR DELAY"  ascii nocase
        $t3 = "BENCHMARK("     ascii nocase
        $t4 = "pg_sleep("      ascii nocase
        $b1 = "AND 1=1"        ascii nocase
        $b2 = "AND 1=2"        ascii nocase
        $b3 = "AND true"       ascii nocase
        $b4 = "AND false"      ascii nocase

    condition:
        any of ($t*) or (2 of ($b*))
}

rule XSS_Attack {
    meta:
        id          = "WEB-003"
        severity    = "medium"
        description = "Cross-site scripting payloads"

    strings:
        $x1 = "<script"            ascii nocase
        $x2 = "javascript:"        ascii nocase
        $x3 = "onerror="           ascii nocase
        $x4 = "onload="            ascii nocase
        $x5 = "alert("             ascii nocase
        $x6 = "document.cookie"    ascii nocase
        $x7 = "eval("              ascii nocase
        $x8 = "<img src=x"         ascii nocase
        $x9 = "&#x3C;script"       ascii nocase  // HTML encoded <script

    condition:
        2 of them
}

rule Path_Traversal {
    meta:
        id          = "WEB-004"
        severity    = "high"
        description = "Directory traversal / LFI attempts"

    strings:
        $p1 = "../../../"    ascii
        $p2 = "..\\..\\..\\" ascii
        $p3 = "%2e%2e%2f"    ascii nocase   // URL encoded ../
        $p4 = "%2e%2e/"      ascii nocase
        $p5 = "..%2f"        ascii nocase
        $p6 = "/etc/passwd"  ascii
        $p7 = "/etc/shadow"  ascii
        $p8 = "boot.ini"     ascii nocase
        $p9 = "win.ini"      ascii nocase

    condition:
        any of them
}

rule Command_Injection {
    meta:
        id          = "WEB-005"
        severity    = "critical"
        description = "OS command injection in HTTP parameters"

    strings:
        $c1 = "; ls "           ascii
        $c2 = "; cat "          ascii
        $c3 = "; id "           ascii
        $c4 = "; whoami"        ascii
        $c5 = "| nc "           ascii
        $c6 = "| bash"          ascii
        $c7 = "`id`"            ascii
        $c8 = "$(id)"           ascii
        $c9 = "%0a id"          ascii nocase   // newline injection
        $ca = "&& dir"          ascii nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// SECTION 2 — MALWARE SIGNATURES
// ─────────────────────────────────────────────────────────────

rule Mimikatz_Network {
    meta:
        id          = "MAL-001"
        severity    = "critical"
        description = "Mimikatz credential dumper strings in traffic"

    strings:
        $m1 = "mimikatz"         ascii nocase wide
        $m2 = "sekurlsa"         ascii nocase wide
        $m3 = "lsadump"          ascii nocase wide
        $m4 = "wdigest"          ascii nocase wide
        $m5 = "kerberos::list"   ascii nocase wide
        $m6 = "privilege::debug" ascii nocase wide

    condition:
        any of them
}

rule Metasploit_Meterpreter {
    meta:
        id          = "MAL-002"
        severity    = "critical"
        description = "Meterpreter reverse shell indicators"

    strings:
        $ms1 = "meterpreter"    ascii nocase
        $ms2 = "ReflectiveDll"  ascii nocase
        $ms3 = "stdapi_"        ascii nocase
        $ms4 = "TLV_TYPE_"      ascii nocase
        $hex_stage = { FC E8 82 00 00 00 }   // common meterpreter shellcode header

    condition:
        any of ($ms*) or $hex_stage
}

rule Webshell_PHP {
    meta:
        id          = "MAL-003"
        severity    = "critical"
        description = "PHP webshell patterns in HTTP response or upload"

    strings:
        $w1 = "eval(base64_decode("   ascii nocase
        $w2 = "eval(gzinflate("       ascii nocase
        $w3 = "system($_GET"          ascii nocase
        $w4 = "passthru($_POST"       ascii nocase
        $w5 = "shell_exec($_REQUEST"  ascii nocase
        $w6 = "preg_replace.*eval"    ascii nocase
        $w7 = "assert($_"             ascii nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// SECTION 3 — C2 / EXFILTRATION
// ─────────────────────────────────────────────────────────────

rule DNS_Tunneling {
    meta:
        id          = "C2-001"
        severity    = "high"
        description = "DNS tunneling — anomalously long subdomains"

    strings:
        // Long base64-like subdomain chunks (common in Iodine, dnscat2)
        $b64_sub = /[A-Za-z0-9+\/]{40,}\.[a-z]{2,6}/

    condition:
        $b64_sub
}

rule HTTP_C2_Beacon {
    meta:
        id          = "C2-002"
        severity    = "high"
        description = "Common C2 framework HTTP beacon user-agents and URIs"

    strings:
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0"  ascii  // Cobalt Strike default
        $ua2 = "python-requests"                     ascii nocase
        $ua3 = "curl/7.43"                           ascii
        $uri1 = "/api/v1/report"   ascii
        $uri2 = "/updates/check"   ascii
        $uri3 = "/submit.php"      ascii
        $hdr1 = "X-Malware-ID:"    ascii nocase

    condition:
        ($ua1 or $ua2 or $ua3) and any of ($uri*, $hdr*)
}

rule Data_Exfiltration_Base64 {
    meta:
        id          = "C2-003"
        severity    = "medium"
        description = "Large base64 blob in HTTP POST — possible data exfil"

    strings:
        // POST with a large contiguous base64 block (>200 chars)
        $post  = "POST " ascii
        $b64lg = /[A-Za-z0-9+\/=]{200,}/

    condition:
        $post and $b64lg
}

// ─────────────────────────────────────────────────────────────
// SECTION 4 — RECONNAISSANCE
// ─────────────────────────────────────────────────────────────

rule Nmap_Scan_Signature {
    meta:
        id          = "RECON-001"
        severity    = "low"
        description = "Nmap default scan user-agent and probe strings"

    strings:
        $n1 = "Nmap Scripting Engine"  ascii nocase
        $n2 = "Nmap"                   ascii nocase
        $n3 = "masscan"                ascii nocase
        $n4 = "ZMap"                   ascii nocase
        $n5 = "User-Agent: Mozilla/5.0 Nmap/" ascii nocase

    condition:
        any of them
}

rule Admin_Panel_Probe {
    meta:
        id          = "RECON-002"
        severity    = "low"
        description = "Brute-force probing for admin panels"

    strings:
        $a1 = "GET /admin"          ascii nocase
        $a2 = "GET /wp-admin"       ascii nocase
        $a3 = "GET /phpmyadmin"     ascii nocase
        $a4 = "GET /.env"           ascii nocase
        $a5 = "GET /config.php"     ascii nocase
        $a6 = "GET /.git/config"    ascii nocase
        $a7 = "GET /server-status"  ascii nocase

    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// SECTION 5 — EXPLOIT FRAMEWORKS
// ─────────────────────────────────────────────────────────────

rule Log4Shell_CVE_2021_44228 {
    meta:
        id          = "CVE-2021-44228"
        severity    = "critical"
        description = "Log4Shell JNDI injection attempt"
        reference   = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"

    strings:
        $j1 = "${jndi:"              ascii nocase
        $j2 = "${${lower:j}ndi:"     ascii nocase  // obfuscation bypass
        $j3 = "${${::-j}${::-n}di:"  ascii nocase
        $j4 = "jndi:ldap://"         ascii nocase
        $j5 = "jndi:rmi://"          ascii nocase
        $j6 = "jndi:dns://"          ascii nocase

    condition:
        any of them
}

rule Spring4Shell_CVE_2022_22965 {
    meta:
        id          = "CVE-2022-22965"
        severity    = "critical"
        description = "Spring4Shell RCE via data binding"

    strings:
        $sp1 = "class.module.classLoader"        ascii
        $sp2 = "classLoader.resources.context"   ascii
        $sp3 = "suffix=.jsp"                     ascii
        $sp4 = "pattern=%25%7Bc2%7Di"            ascii  // URL encoded pattern

    condition:
        2 of them
}
