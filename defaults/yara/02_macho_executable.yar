rule MachO_Executable
{
    meta:
        description = "Identifies macOS Mach-O 64-bit and 32-bit binaries"
        author = "AfterSec EDR"
        severity = "info"

    strings:
        $magic_64 = { CF FA ED FE }
        $magic_32 = { CE FA ED FE }
        $fat_magic = { CA FE BA BE }
        
    condition:
        $magic_64 at 0 or $magic_32 at 0 or $fat_magic at 0
}
