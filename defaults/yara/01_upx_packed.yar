rule UPX_Packed_Binary
{
    meta:
        description = "Detects binaries packed with UPX"
        author = "AfterSec EDR"
        severity = "medium"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX2"
        $upx_magic = { 55 50 58 21 } // UPX!

    condition:
        $upx_magic and 2 of ($upx*)
}
