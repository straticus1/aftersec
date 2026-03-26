# Demo: Automatically re-apply optimal secure kernel variables
def enforce_kernel_security(ctx):
    sysctl_set("net.inet.tcp.blackhole", "2")
    sysctl_set("net.inet.icmp.bmcastecho", "0")
    report_finding("Kernel Tuning", "Sysctls enforced", "Blackhole & ICMP protection activated", "info", "2", "2", True)
