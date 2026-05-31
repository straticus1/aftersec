package main

import (
	"encoding/json"
	"fmt"

	"aftersec/pkg/client/storage"
	"aftersec/pkg/telemetry"
	
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func buildSigmaHunterTab(w fyne.Window, a fyne.App) fyne.CanvasObject {
	ruleEntry := widget.NewMultiLineEntry()
	ruleEntry.TextStyle.Monospace = true
	ruleEntry.SetText(`title: Suspicious Execution from /tmp
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|startswith: '/tmp/'
        CommandLine|contains: 'rm -rf'
    condition: selection`)

	resultsVBox := container.NewVBox()
	resultsScroll := container.NewVScroll(resultsVBox)

	runHuntBtn := widget.NewButton("Run Sigma Hunt on Local Telemetry", func() {
		ruleYAML := ruleEntry.Text
		if ruleYAML == "" {
			dialog.ShowError(fmt.Errorf("sigma rule is empty"), w)
			return
		}

		rule, err := telemetry.ParseSigmaRule([]byte(ruleYAML))
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to parse Sigma YAML: %v", err), w)
			return
		}

		mgr, err := getManager()
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to connect to local telemetry DB: %v", err), w)
			return
		}

		sqliteMgr, ok := mgr.(*storage.SQLiteManager)
		if !ok {
			dialog.ShowError(fmt.Errorf("local telemetry storage is not SQLite"), w)
			return
		}

		resultsVBox.RemoveAll()
		resultsVBox.Add(widget.NewLabel("Hunting... extracting events using JSON1 indexing..."))
		resultsVBox.Refresh()

		go func() {
			events, err := telemetry.RunHunt(sqliteMgr, rule)

			fyne.Do(func() {
				resultsVBox.RemoveAll()
				if err != nil {
					dialog.ShowError(err, w)
					resultsVBox.Add(widget.NewLabel(fmt.Sprintf("Hunt failed: %v", err)))
					resultsVBox.Refresh()
					return
				}

				if len(events) == 0 {
					resultsVBox.Add(widget.NewLabel("✅ No telemetry events matched this Sigma rule."))
				} else {
					resultsVBox.Add(widget.NewLabelWithStyle(fmt.Sprintf("⚠️ Found %d matching events:", len(events)), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
					for _, ev := range events {
						ts := fmt.Sprintf("%v", ev["timestamp"])
						source := fmt.Sprintf("%v", ev["source"])
						
						details := fmt.Sprintf("%v", ev["details"])
						// Format JSON if possible
						var detailsMap map[string]any
						if err := json.Unmarshal([]byte(details), &detailsMap); err == nil {
							prettyDetails, _ := json.MarshalIndent(detailsMap, "", "  ")
							details = string(prettyDetails)
						}

						title := fmt.Sprintf("[%s] %s", ts, source)
						card := widget.NewCard(title, rule.Title, widget.NewLabel(details))
						resultsVBox.Add(card)
					}
				}
				resultsVBox.Refresh()
			})
		}()
	})

	editorSplit := container.NewVSplit(
		container.NewBorder(widget.NewLabel("Sigma Rule YAML Editor:"), runHuntBtn, nil, nil, ruleEntry),
		resultsScroll,
	)
	editorSplit.Offset = 0.4

	return editorSplit
}
