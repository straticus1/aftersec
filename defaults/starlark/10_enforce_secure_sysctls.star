# Check Kernel Security Settings
# Check if secure sysctls are properly configured
tcp_blackhole = sysctl_get("net.inet.tcp.blackhole")
icmp_broadcast = sysctl_get("net.inet.icmp.bmcastecho")

if tcp_blackhole != "2":
    report_finding(
        category="Kernel Tuning",
        name="TCP Blackhole Not Configured",
        desc="TCP blackhole should be set to 2 for better security",
        severity="low",
        current_val=tcp_blackhole,
        expected_val="2",
        passed=False
    )
else:
    report_finding(
        category="Kernel Tuning",
        name="TCP Blackhole Configured",
        desc="TCP blackhole is properly configured",
        severity="info",
        current_val="2",
        expected_val="2",
        passed=True
    )

if icmp_broadcast != "0":
    report_finding(
        category="Kernel Tuning",
        name="ICMP Broadcast Echo Not Disabled",
        desc="ICMP broadcast echo should be disabled for security",
        severity="low",
        current_val=icmp_broadcast,
        expected_val="0",
        passed=False
    )
else:
    report_finding(
        category="Kernel Tuning",
        name="ICMP Broadcast Echo Disabled",
        desc="ICMP broadcast echo is properly disabled",
        severity="info",
        current_val="0",
        expected_val="0",
        passed=True
    )
