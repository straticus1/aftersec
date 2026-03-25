package forensics

import (
	"aftersec/pkg/ai"
	"aftersec/pkg/core"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

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

	// 3. AI and Forensics Hooks
	aiAnalyzeThreat := starlark.NewBuiltin("ai_analyze_threat", func(th *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var telemetry string
		if err := starlark.UnpackArgs("ai_analyze_threat", args, kwargs, "telemetry", &telemetry); err != nil {
			return nil, err
		}
		analysis, err := ai.AnalyzeThreat(context.Background(), telemetry)
		if err != nil {
			return nil, err
		}
		return starlark.String(analysis), nil
	})

	verifySignature := starlark.NewBuiltin("verify_macho_signature", func(th *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path string
		if err := starlark.UnpackArgs("verify_macho_signature", args, kwargs, "path", &path); err != nil {
			return nil, err
		}
		info, err := VerifySignature(path)
		if err != nil {
			return nil, err
		}
		dict := starlark.NewDict(3)
		dict.SetKey(starlark.String("valid"), starlark.Bool(info.Valid))
		dict.SetKey(starlark.String("authority"), starlark.String(info.Authority))
		dict.SetKey(starlark.String("team_id"), starlark.String(info.TeamID))
		return dict, nil
	})

	// Cyber-Warfare Swarm and Honeypot Hooks
	analyzeBinary := starlark.NewBuiltin("ai_analyze_binary", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var filePath string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &filePath); err != nil { return nil, err }
		out, _ := exec.Command("strings", filePath).CombinedOutput()
		strOut := string(out)
		if len(strOut) > 4000 { strOut = strOut[:4000] } // Truncate early to save tokens
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

	// 4. Map the Global environment context
	env := starlark.StringDict{
		"state":                  stateDict,
		"add_finding":            addFinding,
		"ai_analyze_threat":      aiAnalyzeThreat,
		"verify_macho_signature": verifySignature,
		"ai_analyze_binary":      analyzeBinary,
		"deploy_honeypot":        deployHoneypot,
		"ai_swarm_judge":         aiSwarm,
	}

	// 5. Secure Evaluation Sandbox
	_, err := starlark.ExecFile(thread, "rules.star", scriptContent, env)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			return fmt.Errorf("starlark eval error: %v", evalErr.Backtrace())
		}
		return fmt.Errorf("starlark parse error: %w", err)
	}

	return nil
}
