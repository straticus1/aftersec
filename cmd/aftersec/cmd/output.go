package cmd

import (
	"aftersec/pkg/core"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func printState(state *core.SecurityState) {
	if state == nil {
		fmt.Println("No state to display.")
		return
	}
	switch outputFmt {
	case "json":
		b, _ := json.MarshalIndent(state, "", "  ")
		fmt.Println(string(b))
	case "yaml":
		b, _ := yaml.Marshal(state)
		fmt.Println(string(b))
	case "csv":
		w := csv.NewWriter(os.Stdout)
		w.Write([]string{"Category", "Name", "Severity", "Passed", "CurrentVal", "ExpectedVal"})
		for _, f := range state.Findings {
			w.Write([]string{
				f.Category, f.Name, string(f.Severity), fmt.Sprintf("%v", f.Passed), f.CurrentVal, f.ExpectedVal,
			})
		}
		w.Flush()
	default:
		// Table/Text
		fmt.Println("Security Posture Scan Results:")
		fmt.Println("--------------------------------------------------")
		for _, f := range state.Findings {
			status := "PASSED"
			if !f.Passed {
				status = "FAILED"
			}
			fmt.Printf("[%s] %s - %s\n", f.Severity, f.Category, f.Name)
			fmt.Printf("Status:  %s\n", status)
			if !f.Passed {
				fmt.Printf("Current: %s\n", f.CurrentVal)
				fmt.Printf("Expect:  %s\n", f.ExpectedVal)
			}
			fmt.Println("--------------------------------------------------")
		}
	}
}
