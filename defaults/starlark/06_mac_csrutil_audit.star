# Demo: Verify SIP status using system command hook
def audit_system_integrity(ctx):
    out = run_command("csrutil_status")
    if "disabled" in out:
        report_finding("System Integrity", "SIP Disabled", "System Integrity Protection is disabled", "critical", "disabled", "enabled", False)
    else:
        report_finding("System Integrity", "SIP Enabled", "System Integrity Protection is verifying", "info", "enabled", "enabled", True)
