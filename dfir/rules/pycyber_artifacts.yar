/*
    YARA rules for artifacts this project's own modules actually produce.

    Deliberately written against real, reproducible outputs of the demos in
    this repo rather than against malware samples nobody here can legally
    redistribute - every rule below is proven to fire on a specific file
    yara_scanner.py --self-test generates, and proven NOT to fire on a
    benign control file in the same run. A rule that has never been run
    against both a true positive and a true negative is a guess, not a
    detection.

    These are the file/memory-side counterpart to
    detection-engineering/sigma-rules/ - Sigma covers what shows up in logs
    (process creation, command lines), YARA covers what shows up on disk.
    Two of the rules below are deliberately the same heuristic as their
    Sigma equivalent, expressed against file content instead of an event
    log, because that is exactly how the two formats divide the work in a
    real detection pipeline.
*/

import "math"


rule PyCyber_Encoded_PowerShell_Command
{
    meta:
        description = "Base64-encoded or obfuscated PowerShell invocation in a script or dropped file"
        author = "vantage-soc-toolkit"
        attack = "T1059.001, T1027"
        sigma_equivalent = "encoded_or_obfuscated_powershell_command_line.yml"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "HIGH"

    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "FromBase64String" ascii wide nocase
        $exec1 = "IEX(" ascii wide nocase
        $exec2 = "Invoke-Expression" ascii wide nocase
        $ps = "powershell" ascii wide nocase

    condition:
        $ps and (any of ($enc*) or any of ($exec*))
}


rule PyCyber_LOLBin_Download_Cradle
{
    meta:
        description = "Living-off-the-land binary used as a download cradle (certutil/bitsadmin/mshta/regsvr32)"
        author = "vantage-soc-toolkit"
        attack = "T1218, T1105"
        sigma_equivalent = "known_lolbin_process_execution.yml"
        reference = "https://lolbas-project.github.io/"
        severity = "HIGH"

    strings:
        $certutil = "certutil" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase
        $decode   = "-decode" ascii wide nocase
        $bits     = "bitsadmin" ascii wide nocase
        $transfer = "/transfer" ascii wide nocase
        $mshta    = "mshta" ascii wide nocase
        $regsvr   = "regsvr32" ascii wide nocase
        $scrobj   = "scrobj.dll" ascii wide nocase
        $http     = "http" ascii wide nocase

    condition:
        ($certutil and ($urlcache or $decode)) or
        ($bits and $transfer) or
        ($mshta and $http) or
        ($regsvr and $scrobj)
}


rule PyCyber_Staged_Sensitive_Data
{
    meta:
        description = "File containing card-number-shaped and/or SSN-shaped strings alongside exfil-staging keywords"
        author = "vantage-soc-toolkit"
        attack = "T1074.001, T1041"
        reference = "https://attack.mitre.org/techniques/T1074/001/"
        note = "Matches the same patterns exfiltration/exfil_demo.py's DLP inspector looks for in outbound HTTP bodies, applied to data staged on disk before it ever leaves the host."
        severity = "HIGH"

    strings:
        $card = /\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b/
        $ssn  = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/
        $kw1  = "card" ascii nocase
        $kw2  = "ssn" ascii nocase
        $kw3  = "account" ascii nocase
        $kw4  = "ref_id" ascii nocase

    condition:
        ($card or $ssn) and any of ($kw*)
}


rule PyCyber_Ransom_Note
{
    meta:
        description = "Text file with the classic ransom-note vocabulary"
        author = "vantage-soc-toolkit"
        attack = "T1486"
        reference = "https://attack.mitre.org/techniques/T1486/"
        severity = "HIGH"

    strings:
        $enc1 = "your files have been encrypted" ascii wide nocase
        $enc2 = "all of your files are encrypted" ascii wide nocase
        $pay1 = "bitcoin" ascii wide nocase
        $pay2 = "monero" ascii wide nocase
        $pay3 = "ransom" ascii wide nocase
        $act1 = "decrypt" ascii wide nocase
        $act2 = "recovery key" ascii wide nocase

    condition:
        any of ($enc*) and any of ($pay*) and any of ($act*)
}


rule PyCyber_High_Entropy_Blob
{
    meta:
        description = "Small file whose whole content is near-maximum entropy - encrypted or packed, not ordinary document data"
        author = "vantage-soc-toolkit"
        attack = "T1486, T1027.002"
        reference = "https://attack.mitre.org/techniques/T1486/"
        note = "Fires on the AES-256 output of impact/ransomware_sim.py. Entropy alone is a weak signal on its own - compressed archives, media and installers are legitimately high-entropy - so this is scoped to small files and is INFO-to-MEDIUM corroboration, never a standalone verdict. See the scanner's own output caveat."
        severity = "MEDIUM"

    condition:
        filesize > 64 and filesize < 2MB and math.entropy(0, filesize) > 7.2
}
