# System Integrity Checks
# Check if FileVault is enabled
fv_status = run_command("fdesetup", ["status"])
if "FileVault is Off" in fv_status:
    report_finding(
        category="System Integrity",
        name="FileVault Disabled",
        desc="Full disk encryption is not enabled",
        severity="high",
        current_val="off",
        expected_val="on",
        passed=False
    )
else:
    report_finding(
        category="System Integrity",
        name="FileVault Status",
        desc="Full disk encryption is enabled",
        severity="info",
        current_val="on",
        expected_val="on",
        passed=True
    )
