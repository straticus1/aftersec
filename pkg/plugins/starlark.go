package plugins

import (
	"aftersec/pkg/core"
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
			
			if err := starlark.UnpackArgs(b.Name(), args, kwargs,
				"category", &category,
				"name", &name,
				"desc", &desc,
				"severity", &sev,
				"current_val", &currentVal,
				"expected_val", &expected,
				"passed", &passed); err != nil {
				return nil, err
			}

			addFinding(core.Finding{
				Category:     category,
				Name:         fmt.Sprintf("Custom Rule: %s", name),
				Description:  desc,
				Severity:     core.Severity(sev),
				CurrentVal:   currentVal,
				ExpectedVal:  expected,
				LogContext:   "Starlark Script: " + file.Name(),
				Passed:       passed,
			})
			return starlark.None, nil
		})

		env := starlark.StringDict{
			"run_command":    runCmd,
			"report_finding": reportFinding,
		}

		_, err = starlark.ExecFile(thread, path, nil, env)
		if err != nil {
			fmt.Printf("Error executing starlark rule %s: %v\n", file.Name(), err)
		}
	}
}
