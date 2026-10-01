/*
    Memory-resident rules — applied to live process memory, not files.

    Why a separate file: these are written on the assumption that what they
    match may never touch disk at all. The disk rules in
    pycyber_artifacts.yar work fine against memory too (a YARA rule does not
    care where the bytes came from), and yara_scanner.py applies both. What
    could not be written as a disk rule is here.

    The gap this closes, and it is the entire point of memory scanning:
    an attacker who decodes a payload in memory, holds credentials in a
    process after reading them, or injects code into a running process
    leaves nothing on disk for a file scan to find. The project's YARA
    coverage was on-disk only until now, which is exactly the kind of
    limitation worth closing rather than restating.

    Honest scoping, same as the disk rules: every rule here is verified by
    yara_scanner.py --self-test against a real live process that holds the
    pattern in memory, AND against a benign control process that does not.
    Memory scanning produces more false positives than file scanning by its
    nature — a browser tab, a password manager, or a terminal scrollback can
    legitimately hold any string you care to name — so severities here are
    set conservatively and the scanner prints that caveat.
*/


rule PyCyber_Mem_Encoded_PowerShell
{
    meta:
        description = "Encoded/obfuscated PowerShell held in a live process's memory"
        author = "vantage-soc-toolkit"
        attack = "T1059.001, T1027"
        reference = "https://attack.mitre.org/techniques/T1027/"
        note = "The same heuristic as the disk rule, but a hit here means the command is resident in a running process — which is where it ends up even when the dropper that carried it was never written to disk."
        severity = "HIGH"
        scope = "memory"

    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "FromBase64String" ascii wide nocase
        $exec = "Invoke-Expression" ascii wide nocase
        $ps   = "powershell" ascii wide nocase

    condition:
        $ps and any of ($enc1, $enc2, $exec)
}


rule PyCyber_Mem_Credential_Material
{
    meta:
        description = "Access-key-shaped and secret-shaped strings resident together in process memory"
        author = "vantage-soc-toolkit"
        attack = "T1555, T1552.001"
        reference = "https://attack.mitre.org/techniques/T1555/"
        note = "Matches the shape of what shield-legitimize/honeytoken_watcher.py deploys and what credential-access/credential_access_demo.py harvests. A process holding BOTH an access-key-shaped token and secret-key vocabulary is the signal; either alone is ordinary."
        severity = "MEDIUM"
        scope = "memory"

    strings:
        $akia = /AKIA[A-Z0-9]{16}/ ascii wide
        $sec1 = "AWS_SECRET_ACCESS_KEY" ascii wide nocase
        $sec2 = "SECRET_ACCESS_KEY" ascii wide nocase
        $sec3 = "aws_backup_credentials" ascii wide nocase

    condition:
        $akia and any of ($sec*)
}
