# Process Security Monitoring
# Scan running processes for suspicious patterns
procs = scan_processes()
suspicious_found = False
for p in procs:
    if p["score"] > 50:
        report_finding(
            category="Process Security",
            name="Suspicious Process: " + p["command"],
            desc="Process detected with suspicious characteristics: " + p["reason"],
            severity="medium",
            current_val="score: " + str(p["score"]),
            expected_val="score: <50",
            passed=False,
            remediation_script=p["kill_command"]
        )
        suspicious_found = True

if not suspicious_found:
    report_finding(
        category="Process Security",
        name="Process Scan Complete",
        desc="No suspicious processes detected",
        severity="info",
        current_val="clean",
        expected_val="clean",
        passed=True
    )
