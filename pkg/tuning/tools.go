package tuning

import (
	"aftersec/pkg/core"
)

func PurgeRAM() error {
	script := "purge"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func FlushDNS() error {
	script := "dscacheutil -flushcache; killall -HUP mDNSResponder"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}

func ResetTCC() error {
	script := "tccutil reset All"
	core.RegisterAllowedScript(script)
	return core.RunPrivileged(script)
}
