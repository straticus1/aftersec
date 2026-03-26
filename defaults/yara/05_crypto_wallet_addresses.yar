rule Crypto_Wallet_Artifacts
{
    meta:
        description = "Detects embedded cryptocurrency wallet addresses (BTC/ETH) common in cryptominers and ransomware"
        author = "AfterSec EDR"
        severity = "medium"

    strings:
        $btc_legacy = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $btc_segwit = /bc1[ac-hj-np-z02-9]{11,71}/ ascii wide
        $eth = /0x[a-fA-F0-9]{40}/ ascii wide

    condition:
        any of them
}
