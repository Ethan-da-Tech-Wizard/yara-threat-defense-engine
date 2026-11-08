// TWU local self-test rule. Not from any upstream. Proves the YARA engine path works end to end.
rule TWU_EICAR_Test_String {
    meta:
        description = "Detects the harmless industry-standard EICAR antivirus test string"
        author = "TWU LLC"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $e
}
