/*
    🛡️ FILE INTEGRITY MONITORING - THREAT DETECTION RULES
    =====================================================
    DISCLAIMER:
    This YARA ruleset is provided for showcase purposes only. Actual production configurations, credentials, and infrastructure details are managed securely and are not included in this repository.
    It demonstrates common detection patterns for PHP-based threats and
    does not represent a complete or production-hardened security policy.

    False positives may occur. Rules should be tuned and validated before
    use in any real production environment.
    
*/


rule PHP_Dangerous_Functions {
    meta:
        description = "Detects critical system execution functions often used by malware"
        severity = "Critical"
        author = "Ichramsyah"
    strings:
        $cmd1 = "shell_exec" nocase
        $cmd2 = "exec(" nocase
        $cmd3 = "system(" nocase
        $cmd4 = "passthru" nocase
        $cmd5 = "proc_open" nocase
        $cmd6 = "popen" nocase
        $cmd7 = "pcntl_exec" nocase
        $backtick = /\x60[^\x60]+\x60/ 
    condition:
        any of them
}

rule PHP_Webshell_Payload {
    meta:
        description = "Detects Remote Code Execution (RCE) via User Input (Classic Webshell Pattern)"
        severity = "High"
        author = "Ichramsyah"
    strings:
        $input1 = "$_GET" nocase
        $input2 = "$_POST" nocase
        $input3 = "$_REQUEST" nocase
        $input4 = "$_COOKIE" nocase
        
        $sink1 = "eval" nocase
        $sink2 = "assert" nocase
    condition:
        ($sink1 or $sink2) and any of ($input*)
}

rule PHP_Obfuscated_Code {
    meta:
        description = "Detects obfuscated or hidden code execution attempts"
        severity = "Suspicious"
        author = "Ichramsyah"
    strings:
        $b64_eval = "eval(base64_decode" nocase
        $gz_eval  = "eval(gzinflate" nocase
        $silent   = "@eval" nocase
        $silent_inc = "@include" nocase
        $hex_pattern = /\\x[0-9A-Fa-f]{2}\\x[0-9A-Fa-f]{2}\\x[0-9A-Fa-f]{2}/
    condition:
        $b64_eval or $gz_eval or $silent or $silent_inc or ($hex_pattern and filesize < 100KB)
}

rule PHP_System_Recon {
    meta:
        description = "Detects attempts to access sensitive system files or recon commands"
        severity = "High"
        author = "Ichramsyah"
    strings:
        $file1 = "/etc/passwd" nocase
        $file2 = "/etc/shadow" nocase
        $sh1   = "/bin/bash" nocase
        $sh2   = "/bin/sh" nocase
        
        $tool1 = "wget" nocase
        $tool2 = "curl" nocase
        $tool3 = "whoami" nocase
    condition:
        2 of them
}