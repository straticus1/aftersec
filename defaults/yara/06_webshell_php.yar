rule PHP_Webshell_Characteristics
{
    meta:
        description = "Detects common PHP webshell execution components"
        author = "AfterSec EDR"
        severity = "high"

    strings:
        $eval = "eval(base64_decode" ascii nocase
        $cmd = "$_REQUEST['cmd']" ascii nocase
        $exec = "shell_exec(" ascii nocase
        $sys = "system(" ascii nocase
        $passthru = "passthru(" ascii nocase
        
    condition:
        2 of them
}
