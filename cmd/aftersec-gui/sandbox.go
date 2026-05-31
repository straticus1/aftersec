package main

import (
	"context"
	"fmt"
	"time"

	"aftersec/pkg/forensics"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func buildSandboxTab(w fyne.Window) fyne.CanvasObject {
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("Enter full path to macOS binary (Mach-O) to trace...")

	resultsVBox := container.NewVBox()
	resultsScroll := container.NewVScroll(resultsVBox)

	runBtn := widget.NewButton("Launch Unicorn Sandbox Emulation", func() {
		if pathEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("please specify a binary path"), w)
			return
		}

		resultsVBox.RemoveAll()
		resultsVBox.Add(widget.NewLabelWithStyle("🦄 Booting Unicorn Microscopic Arch Emulator...", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}))
		
		progress := widget.NewProgressBarInfinite()
		resultsVBox.Add(progress)
		resultsVBox.Refresh()

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			
			start := time.Now()
			report, err := forensics.EmulateMachO(ctx, pathEntry.Text)
			duration := time.Since(start)

			fyne.Do(func() {
				resultsVBox.RemoveAll()
				if err != nil && report == nil {
					dialog.ShowError(err, w)
					resultsVBox.Add(widget.NewLabel("Crash/Error: " + err.Error()))
					return
				}

				title := widget.NewLabelWithStyle(fmt.Sprintf("Emulation Finished in %v", duration), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
				resultsVBox.Add(title)

				statsGrid := container.NewGridWithColumns(2,
					widget.NewLabel("Architecture:"), widget.NewLabel(report.Architecture),
					widget.NewLabel("Simulated Instructions:"), widget.NewLabel(fmt.Sprintf("%d", report.Instructions)),
					widget.NewLabel("Syscalls / Traps:"), widget.NewLabel(fmt.Sprintf("%d", report.Syscalls)),
					widget.NewLabel("High-Entropy Loops:"), widget.NewLabel(fmt.Sprintf("%d", report.UnpackingLoops)),
				)
				
				scoreColor := "🟢 SAFE"
				if report.Score >= 50 {
					scoreColor = "🔴 MALICIOUS (High Intent Score)"
				} else if report.Score >= 20 {
					scoreColor = "🟡 SUSPICIOUS"
				}

				resultsVBox.Add(widget.NewCard("Behavioral Intent Score", fmt.Sprintf("%d / 100", report.Score), widget.NewLabel(scoreColor)))
				resultsVBox.Add(widget.NewCard("Sandbox Execution Stats", "", statsGrid))

				if report != nil && report.HasError {
					resultsVBox.Add(widget.NewCard("Sandbox Halted / Exceptions", "", widget.NewLabel(report.ErrorMessage)))
				}
				
				// Graphical block representation
				if report != nil && report.Instructions > 0 {
					graphDesc := "API Routing / Basic Block Graph:\n"
					graphDesc += "[Entry Point] -> "
					if report.UnpackingLoops > 0 {
						graphDesc += fmt.Sprintf("[Self-Modifying Loop x%d] -> ", report.UnpackingLoops)
					}
					if report.Syscalls > 0 {
						graphDesc += fmt.Sprintf("[Syscalls x%d] -> ", report.Syscalls)
					}
					graphDesc += "[Halt]"
					resultsVBox.Add(widget.NewCard("Execution Path Graph", "Simplified Behavioral Trajectory", widget.NewLabel(graphDesc)))
				}

				resultsVBox.Refresh()
			})
		}()
	})

	return container.NewBorder(
		container.NewBorder(nil, nil, nil, runBtn, pathEntry),
		nil, nil, nil,
		resultsScroll,
	)
}
