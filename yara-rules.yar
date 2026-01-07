/*
    YARA Ruleset for PHP Webshell & Malware Detection
    Author: Ichramsyah
    Date: 2026-01-05
    Description: Targeted rules to identify Remote Code Execution (RCE), 
                 obfuscation, and system reconnaissance patterns in PHP.
*/

rule PHP_Dangerous_Functions {
    meta:
        description = "Mendeteksi fungsi PHP eksekusi sistem"
        severity = "Critical"
    strings:
        $cmd1 = "shell_exec" nocase
        $cmd2 = "exec(" nocase
        $cmd3 = "system(" nocase
        $cmd4 = "passthru" nocase
        $cmd5 = "proc_open" nocase
        $cmd6 = "popen" nocase
        $cmd7 = "pcntl_exec" nocase
        $backtick = /`.*`/ 
    condition:
        any of them
}

rule PHP_Webshell_Payload {
    meta:
        description = "Mendeteksi input user yang dieksekusi (RCE)"
        severity = "High"
    strings:
        $get = "$_GET" nocase
        $post = "$_POST" nocase
        $req = "$_REQUEST" nocase
        $cookie = "$_COOKIE" nocase
        $eval = "eval" nocase
        $assert = "assert" nocase
    condition:
        ($eval or $assert) and ($get or $post or $req or $cookie)
}

rule PHP_Obfuscated_Code {
    meta:
        description = "Mendeteksi kode yang disamarkan"
        severity = "Suspicious"
    strings:
        $b64_eval = "eval(base64_decode" nocase
        $gz_eval = "eval(gzinflate" nocase
        // Escape character \\x untuk hex
        $hex = /\\x[0-9A-Fa-f]{2}\\x[0-9A-Fa-f]{2}\\x[0-9A-Fa-f]{2}/
        $silent = "@eval" nocase
        $silent_inc = "@include" nocase
    condition:
        $b64_eval or $gz_eval or $silent or $silent_inc or ($hex and filesize < 50KB)
}

rule PHP_System_Recon {
    meta:
        description = "Mencoba akses file sensitif"
        severity = "High"
    strings:
        $f1 = "/etc/passwd" nocase
        $f2 = "/etc/shadow" nocase
        $f3 = "/bin/bash" nocase
        $f4 = "/bin/sh" nocase
        $f5 = "wget" nocase
        $f6 = "curl" nocase
        $f7 = "whoami" nocase
    condition:
        2 of them
}