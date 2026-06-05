//go:build darwin

package tuning

func GetRecommendedSysctls() []SysctlVariable {
	return []SysctlVariable{
		{"net.inet.icmp.drop_redirect", "1", "Drop ICMP redirects (prevents routing attacks)"},
		{"net.inet.tcp.blackhole", "2", "Drop packets to closed TCP ports"},
		{"net.inet.udp.blackhole", "1", "Drop packets to closed UDP ports"},
		{"net.inet.tcp.delayed_ack", "0", "Disable TCP Delayed ACK for lower latency"},
		{"net.inet.icmp.bmcastecho", "0", "Ignore ICMP broadcast requests (smurf attacks)"},
		{"net.inet.tcp.fastopen", "3", "Enable TCP Fast Open (performance optimization)"},
		{"kern.maxfiles", "204800", "Increase maximum number of open files"},
		{"kern.maxvnodes", "250000", "Increase maximum vnodes for high disk I/O"},
		{"net.inet.tcp.mssdflt", "1440", "Optimize TCP MSS for better throughput"},
	}
}
