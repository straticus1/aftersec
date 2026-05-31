package main

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"aftersec/pkg/forensics"
)

// buildContainerTab constructs the macOS Container analysis pane
func buildContainerTab(w fyne.Window) fyne.CanvasObject {
	title := widget.NewLabelWithStyle("📦 Deep Container Forensics", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	desc := widget.NewLabel("Analyze macOS proprietary container structures natively to uncover tampering and hidden scripts.")

	resultBox := widget.NewMultiLineEntry()
	resultBox.Wrapping = fyne.TextWrapWord
	// Use an entry that doesn't capture editing focus for cleaner UX on massive results
	resultBox.Disable() 

	analyzeAppBtn := widget.NewButton("Select .app Bundle (Signature Engine)", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			resultBox.SetText(fmt.Sprintf("🔍 Analyzing Cryptographic Seal for: %s\n...", uri.Path()))

			go func() {
				res, err := forensics.VerifyMacBundle(context.Background(), uri.Path())
				var out string
				if err != nil {
					out = fmt.Sprintf("❌ Structural parsing failed: %v", err)
				} else {
					if res.IsValid {
						out = fmt.Sprintf("✅ Status: SOUND & TRUSTED\nTeamID: %s\nAuthority: %s\n", res.TeamID, res.Authority)
					} else {
						out = "❌ Status: COMPROMISED OR UNTRUSTED\n"
						if res.IsAdHoc {
							out += "WARNING: Ad-Hoc Signature Detected\n"
						}
						for _, issue := range res.Issues {
							out += fmt.Sprintf(" - %s\n", issue)
						}
					}
					out += "\n\nRaw Core Output:\n" + res.RawOutput
				}
				
				// Ensure Fyne thread safety during component update
				resultBox.SetText(out)
				resultBox.Refresh()
			}()
		}, w)
	})

	analyzePkgBtn := widget.NewButton("Select .pkg Installer (XAR Extractor)", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			path := reader.URI().Path()
			reader.Close()

			resultBox.SetText(fmt.Sprintf("📦 Bursting XAR Sandbox for: %s\n...", path))

			go func() {
				res, err := forensics.AnalyzeInstaller(context.Background(), path)
				var out string
				if err != nil {
					out = fmt.Sprintf("❌ Fatal Extraction Fault: %v", err)
				} else {
					if res.Error != nil {
						out = fmt.Sprintf("⚠️ Sandbox Execution Error: %v\n", res.Error)
					} else if res.RawScriptsExtracted == 0 {
						out = "✅ Status: Clean\nNo implicit root-level pre/post install scripts detected in XAR."
					} else {
						out = fmt.Sprintf("⚠️ Status: ROOT SCRIPTS PRESENT (%d found)\n", res.RawScriptsExtracted)
						if res.PreinstallScript != "" {
							out += "\n--- PREINSTALL SCRIPT ---\n" + res.PreinstallScript
						}
						if res.PostinstallScript != "" {
							out += "\n--- POSTINSTALL SCRIPT ---\n" + res.PostinstallScript
						}
					}
				}
				// Ensure Fyne thread safety during component update
				resultBox.SetText(out)
				resultBox.Refresh()
			}()
		}, w)
	})

	controls := container.NewHBox(analyzeAppBtn, analyzePkgBtn)
	
	return container.NewBorder(
		container.NewVBox(title, desc, controls),
		nil, nil, nil,
		resultBox,
	)
}
