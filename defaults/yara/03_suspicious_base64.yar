rule Suspicious_Base64_Payload
{
    meta:
        description = "Detects abnormally long Base64 strings common in obfuscated payloads"
        author = "AfterSec EDR"
        severity = "medium"

    strings:
        // Match a contiguous base64 string of at least 300 characters
        $b64 = /[A-Za-z0-9+\/]{300,}={0,2}/

    condition:
        $b64
}
