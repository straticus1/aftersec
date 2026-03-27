# Code Signature Verification
# Verify signatures of critical system applications
critical_apps = ["/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                 "/Applications/Safari.app/Contents/MacOS/Safari"]
unsigned_found = False

for app_path in critical_apps:
    sig = verify_signature(app_path)
    if not sig["valid"]:
        report_finding(
            category="Code Integrity",
            name="Invalid Signature: " + app_path,
            desc="Application signature verification failed",
            severity="critical",
            current_val="invalid",
            expected_val="valid Apple signature",
            passed=False
        )
        unsigned_found = True
    elif "Apple" not in sig["authority"]:
        report_finding(
            category="Code Integrity",
            name="Non-Apple Signature: " + app_path,
            desc="Application not signed by Apple: " + sig["authority"],
            severity="high",
            current_val=sig["authority"],
            expected_val="Apple Inc.",
            passed=False
        )
        unsigned_found = True

if not unsigned_found:
    report_finding(
        category="Code Integrity",
        name="App Signature Check",
        desc="All critical applications properly signed",
        severity="info",
        current_val="verified",
        expected_val="verified",
        passed=True
    )
