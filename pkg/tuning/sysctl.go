package tuning

import (
	"aftersec/pkg/core"
	"fmt"
	"os/exec"
	"strings"
)

type SysctlVariable struct {
	Name        string
	Value       string
	Description string
}

func GetSysctl(name string) (string, error) {
	out, err := exec.Command("sysctl", "-n", name).CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func SetSysctl(name, value string) error {
	script := fmt.Sprintf("sysctl -w %s=%s", name, value)
	core.RegisterAllowedScript(script)
	
	err := core.RunPrivileged(script)
	if err != nil {
		return err
	}
	
	persistScript := fmt.Sprintf(`echo "\n%s=%s" >> /etc/sysctl.conf`, name, value)
	core.RegisterAllowedScript(persistScript)
	return core.RunPrivileged(persistScript)
}

func GetRecommendedSysctls() []SysctlVariable {
	return []SysctlVariable{
		{"net.inet.icmp.drop_redirect", "1", "Drop ICMP redirects (prevents routing attacks)"},
		{"net.inet.tcp.blackhole", "2", "Drop packets to closed TCP ports"},
		{"net.inet.udp.blackhole", "1", "Drop packets to closed UDP ports"},
		{"net.inet.tcp.delayed_ack", "0", "Disable TCP Delayed ACK for lower latency"},
		{"kern.maxfiles", "204800", "Increase maximum number of open files"},
		{"kern.maxvnodes", "250000", "Increase maximum vnodes for high disk I/O"},
		{"net.inet.tcp.mssdflt", "1440", "Optimize TCP MSS for better throughput"},
	}
}
