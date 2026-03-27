# Crypto Miner Detection
# Scan for known cryptocurrency mining processes
procs = scan_processes()
miners = ["minerd", "xmrig", "ccminer", "ethminer", "cgminer"]
miner_found = False

for p in procs:
    for miner in miners:
        if miner in p["command"].lower():
            report_finding(
                category="Malware Detection",
                name="Crypto Miner Detected: " + miner,
                desc="Known cryptocurrency mining process found: " + p["command"],
                severity="critical",
                current_val="running",
                expected_val="not present",
                passed=False,
                remediation_script=p["kill_command"]
            )
            miner_found = True

if not miner_found:
    report_finding(
        category="Malware Detection",
        name="Crypto Miner Scan",
        desc="No cryptocurrency miners detected",
        severity="info",
        current_val="clean",
        expected_val="clean",
        passed=True
    )
