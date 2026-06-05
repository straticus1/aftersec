//go:build linux

package tuning

func GetRecommendedSysctls() []SysctlVariable {
	return []SysctlVariable{
		{"net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore ICMP broadcasts (prevents Smurf attacks)"},
		{"net.ipv4.conf.all.accept_redirects", "0", "Reject ICMP redirects (prevents routing attacks)"},
		{"net.ipv4.conf.all.send_redirects", "0", "Do not send ICMP redirects"},
		{"net.ipv4.tcp_syncookies", "1", "Enable SYN cookie protection against SYN flood attacks"},
		{"net.ipv4.conf.all.rp_filter", "1", "Enable reverse path filtering (anti-spoofing)"},
		{"net.ipv4.tcp_fin_timeout", "30", "Reduce TIME_WAIT state duration (seconds)"},
		{"kernel.dmesg_restrict", "1", "Restrict dmesg output to privileged users"},
		{"kernel.perf_event_paranoid", "3", "Restrict perf events to privileged users"},
		{"net.ipv4.conf.all.log_martians", "1", "Log packets with invalid source addresses"},
	}
}
