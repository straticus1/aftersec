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
