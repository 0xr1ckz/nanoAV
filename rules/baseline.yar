rule suspicious_powershell {
    meta:
        description = "Encoded PowerShell execution"
        severity    = "high"
    strings:
        $enc  = "powershell" nocase
        $flag = "-EncodedCommand" nocase
        $b64  = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $enc and ($flag or $b64)
}

rule shellcode_nop_sled {
    meta:
        description = "NOP sled — classic shellcode preamble"
        severity    = "critical"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule mz_in_non_header_region {
    meta:
        description = "PE MZ header in unexpected region — possible injection"
        severity    = "high"
    strings:
        $mz = { 4D 5A }
    condition:
        #mz > 1
}