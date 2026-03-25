package plugins

import (
	"aftersec/pkg/ai"
	"aftersec/pkg/core"
	"aftersec/pkg/forensics"
	"aftersec/pkg/tuning"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

const RulesDirectory = "/etc/aftersec/rules"

var allowedCommands = map[string][]string{
	"defaults_read":    {"defaults", "read"},
	"system_profiler":  {"system_profiler"},
	"csrutil_status":   {"csrutil", "status"},
	"spctl_status":     {"spctl", "--status"},
	"pmset":            {"pmset", "-g"},
	"networksetup":     {"networksetup"},
	"diskutil":         {"diskutil", "info"},
	"fdesetup":         {"fdesetup", "status"},
}

func NumStarlarkRules() int {
	files, err := os.ReadDir(RulesDirectory)
	if err != nil {
		return 0
	}
	count := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".star") {
			count++
		}
	}
	return count
}

func ScanStarlark(addFinding func(core.Finding)) {
	if _, err := os.Stat(RulesDirectory); os.IsNotExist(err) {
		return
	}

	files, err := os.ReadDir(RulesDirectory)
	if err != nil {
		return
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".star") {
			continue
		}

		path := filepath.Join(RulesDirectory, file.Name())
		thread := &starlark.Thread{Name: "aftersec-plugin"}

		runCmd := starlark.NewBuiltin("run_command", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var cmdName string
			var cmdArgs *starlark.List
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cmd", &cmdName, "args?", &cmdArgs); err != nil {
				return nil, err
			}

			allowedCmd, ok := allowedCommands[cmdName]
			if !ok {
				return nil, fmt.Errorf("command %q not in allowlist", cmdName)
			}

			cmdParts := make([]string, len(allowedCmd))
			copy(cmdParts, allowedCmd)

			if cmdArgs != nil {
				iter := cmdArgs.Iterate()
				defer iter.Done()
				var val starlark.Value
				for iter.Next(&val) {
					if str, ok := val.(starlark.String); ok {
						arg := string(str)
						if strings.ContainsAny(arg, ";|&$`\n") {
							return nil, fmt.Errorf("invalid characters in argument")
						}
						cmdParts = append(cmdParts, arg)
					}
				}
			}

			out, _ := exec.Command(cmdParts[0], cmdParts[1:]...).CombinedOutput()
			return starlark.String(strings.TrimSpace(string(out))), nil
		})

		reportFinding := starlark.NewBuiltin("report_finding", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var category, name, desc, sev, currentVal, expected string
			var passed bool
			var remediationScript string
			
			if err := starlark.UnpackArgs(b.Name(), args, kwargs,
				"category", &category,
				"name", &name,
				"desc", &desc,
				"severity", &sev,
				"current_val", &currentVal,
				"expected_val", &expected,
				"passed", &passed,
				"remediation_script?", &remediationScript); err != nil {
				return nil, err
			}

			addFinding(core.Finding{
				Category:          category,
				Name:              fmt.Sprintf("Custom Rule: %s", name),
				Description:       desc,
				Severity:          core.Severity(sev),
				CurrentVal:        currentVal,
				ExpectedVal:       expected,
				LogContext:        "Starlark Script: " + file.Name(),
				Passed:            passed,
				RemediationScript: remediationScript,
			})
			return starlark.None, nil
		})

		sysctlGet := starlark.NewBuiltin("sysctl_get", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil { return nil, err }
			val, err := tuning.GetSysctl(name)
			if err != nil { return nil, err }
			return starlark.String(val), nil
		})

		sysctlSet := starlark.NewBuiltin("sysctl_set", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name, val string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "val", &val); err != nil { return nil, err }
			return starlark.None, tuning.SetSysctl(name, val)
		})

		toggleFeature := starlark.NewBuiltin("toggle_feature", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var domain, key string
			var enabled bool
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "domain", &domain, "key", &key, "enabled", &enabled); err != nil { return nil, err }
			return starlark.None, tuning.SetBooleanDefault(domain, key, enabled)
		})

		scanProcesses := starlark.NewBuiltin("scan_processes", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			procs, err := forensics.ScanRunningProcesses()
			if err != nil { return nil, err }
			list := starlark.NewList(nil)
			for _, p := range procs {
				dict := starlark.NewDict(10)
				dict.SetKey(starlark.String("pid"), starlark.MakeInt(p.PID))
				dict.SetKey(starlark.String("user"), starlark.String(p.User))
				dict.SetKey(starlark.String("command"), starlark.String(p.Command))
				dict.SetKey(starlark.String("path"), starlark.String(p.Path))
				dict.SetKey(starlark.String("net_count"), starlark.MakeInt(p.NetCount))
				dict.SetKey(starlark.String("score"), starlark.MakeInt(int(p.Score)))
				dict.SetKey(starlark.String("reason"), starlark.String(p.Reason))
				dict.SetKey(starlark.String("kill_command"), starlark.String(p.KillCommand))
				list.Append(dict)
			}
			return list, nil
		})

		simpleTool := func(name string, f func() error) *starlark.Builtin {
			return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				return starlark.None, f()
			})
		}

		aiAnalyzeThreat := starlark.NewBuiltin("ai_analyze_threat", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var telemetry string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "telemetry", &telemetry); err != nil { return nil, err }
			analysis, err := ai.AnalyzeThreat(context.Background(), telemetry)
			if err != nil { return nil, err }
			return starlark.String(analysis), nil
		})

		verifySignature := starlark.NewBuiltin("verify_signature", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var filePath string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &filePath); err != nil { return nil, err }
			info, err := forensics.VerifySignature(filePath)
			if err != nil { return nil, err }
			dict := starlark.NewDict(3)
			dict.SetKey(starlark.String("valid"), starlark.Bool(info.Valid))
			dict.SetKey(starlark.String("authority"), starlark.String(info.Authority))
			dict.SetKey(starlark.String("team_id"), starlark.String(info.TeamID))
			return dict, nil
		})

		analyzeBinary := starlark.NewBuiltin("ai_analyze_binary", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var filePath string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &filePath); err != nil { return nil, err }
			out, _ := exec.Command("strings", filePath).CombinedOutput()
			strOut := string(out)
			if len(strOut) > 4000 { strOut = strOut[:4000] }
			analysis, err := ai.AnalyzeBinarySemantics(context.Background(), strOut)
			if err != nil { return nil, err }
			return starlark.String(analysis), nil
		})

		deployHoneypot := starlark.NewBuiltin("deploy_honeypot", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var decoyType, destPath string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "type", &decoyType, "path", &destPath); err != nil { return nil, err }
			content, err := ai.GenerateHoneypotContent(context.Background(), decoyType)
			if err != nil { return nil, err }
			if err := os.WriteFile(destPath, []byte(content), 0644); err != nil { return nil, err }
			return starlark.String("Honeypot Deployed"), nil
		})

		aiSwarm := starlark.NewBuiltin("ai_swarm_judge", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var telemetry string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "telemetry", &telemetry); err != nil { return nil, err }
			analysis, err := ai.AnalyzeThreatSwarm(context.Background(), telemetry)
			if err != nil { return nil, err }
			return starlark.String(analysis), nil
		})

		env := starlark.StringDict{
			"run_command":    runCmd,
			"report_finding": reportFinding,
			"sysctl_get":     sysctlGet,
			"sysctl_set":     sysctlSet,
			"toggle_feature": toggleFeature,
			"scan_processes": scanProcesses,
			"purge_ram":      simpleTool("purge_ram", tuning.PurgeRAM),
			"flush_dns":      simpleTool("flush_dns", tuning.FlushDNS),
			"clear_caches":   simpleTool("clear_caches", tuning.ClearSystemCaches),
			"empty_trash":    simpleTool("empty_trash", tuning.EmptyTrash),
			"ai_analyze_threat": aiAnalyzeThreat,
			"verify_signature":  verifySignature,
			"ai_analyze_binary": analyzeBinary,
			"deploy_honeypot":   deployHoneypot,
			"ai_swarm_judge":    aiSwarm,
		}

		_, err = starlark.ExecFile(thread, path, nil, env)
		if err != nil {
			fmt.Printf("Error executing starlark rule %s: %v\n", file.Name(), err)
		}
	}
}
