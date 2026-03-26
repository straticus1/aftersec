rule Reverse_Shell_Artifacts
{
    meta:
        description = "Detects common bash/python reverse shell one-liners inside scripts or binaries"
        author = "AfterSec EDR"
        severity = "high"

    strings:
        $bash_tcp = "/dev/tcp/" ascii wide
        $bash_udp = "/dev/udp/" ascii wide
        $python_pty = "pty.spawn(\"/bin/bash\")" ascii wide
        $netcat_e = "nc -e /bin/sh" ascii wide
        
    condition:
        any of them
}
