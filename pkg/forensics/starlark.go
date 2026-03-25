package forensics

import (
	"aftersec/pkg/core"
	"fmt"
	"log"

	"go.starlark.net/starlark"
)

// EvaluateRules safely executes an untrusted Python-like Starlark script
// against the localized Go macOS SecurityState memory object.
func EvaluateRules(scriptContent string, state *core.SecurityState) error {
	thread := &starlark.Thread{Name: "aftersec-rules"}

	// 1. Flatten the inner Go structs into Starlark dictionaries
	var values []starlark.Value
	for _, f := range state.Findings {
		fDict := starlark.NewDict(4)
		fDict.SetKey(starlark.String("name"), starlark.String(f.Name))
		fDict.SetKey(starlark.String("category"), starlark.String(f.Category))
		fDict.SetKey(starlark.String("passed"), starlark.Bool(f.Passed))
		fDict.SetKey(starlark.String("current_val"), starlark.String(f.CurrentVal))
		values = append(values, fDict)
	}

	starlarkFindings := starlark.NewList(values)

	stateDict := starlark.NewDict(1)
	stateDict.SetKey(starlark.String("findings"), starlarkFindings)

	// 2. Build our explicit external Hooks for the script to call back into Go
	addFinding := starlark.NewBuiltin("add_finding", func(th *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name, category, severity, desc string
		if err := starlark.UnpackArgs("add_finding", args, kwargs, "name", &name, "category", &category, "severity", &severity, "desc", &desc); err != nil {
			return nil, err
		}

		newFinding := core.Finding{
			Name:        name,
			Category:    category,
			Severity:    core.Severity(severity),
			Description: desc,
			Passed:      false,
		}

		state.Findings = append(state.Findings, newFinding)
		log.Printf("[Starlark Engine] Inserted custom rule violation from dynamic evaluation: %s", newFinding.Name)
		
		return starlark.None, nil
	})

	// 3. Map the Global environment context
	env := starlark.StringDict{
		"state":       stateDict,
		"add_finding": addFinding,
	}

	// 4. Secure Evaluation Sandbox
	_, err := starlark.ExecFile(thread, "rules.star", scriptContent, env)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			return fmt.Errorf("starlark eval error: %v", evalErr.Backtrace())
		}
		return fmt.Errorf("starlark parse error: %w", err)
	}

	return nil
}
