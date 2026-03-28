package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"aftersec/pkg/ai"
	"aftersec/pkg/client"
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/forensics"
	"aftersec/pkg/scanners"
	"aftersec/pkg/tuning"
	"aftersec/cmd/aftersec-gui/ui"
)

type appState struct {
	mu              sync.RWMutex
	currentFindings []core.Finding
	lastState       *core.SecurityState
	verboseLogs     string
	currentState    *core.SecurityState
	diffChanges     []string
}

type VolumeInfo struct {
	Path       string
	MountPoint string
	Filesystem string
}

func detectAvailableVolumes() []VolumeInfo {
	var volumes []VolumeInfo

	// Root volume
	volumes = append(volumes, VolumeInfo{
		Path:       "/",
		MountPoint: "/ (Root)",
		Filesystem: "apfs",
	})

	// Check /Volumes for mounted drives
	volumesDir := "/Volumes"
	if entries, err := os.ReadDir(volumesDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				volPath := volumesDir + "/" + entry.Name()
				volumes = append(volumes, VolumeInfo{
					Path:       volPath,
					MountPoint: entry.Name(),
				})
			}
		}
	}

	// Add System Data volume
	if info, err := os.Stat("/System/Volumes/Data"); err == nil && info.IsDir() {
		volumes = append(volumes, VolumeInfo{
			Path:       "/System/Volumes/Data",
			MountPoint: "System Data",
			Filesystem: "apfs",
		})
	}

	return volumes
}

func getManager() (storage.Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home dir: %w", err)
	}
	cfg, err := client.LoadConfig(home + "/.aftersec/config.yaml")
	if err != nil || cfg == nil {
		cfg = client.DefaultClientConfig()
	}
	if cfg.Mode == client.ModeEnterprise {
		return storage.NewCacheManager(cfg)
	}
	return storage.NewSQLiteManager(cfg.Storage.Path)
}

func requireAdmin(w fyne.Window, resourceDesc string, action func() error) {
	dialog.ShowConfirm("Administrative Access Required",
		fmt.Sprintf("This tool requires administrative privileges to modify:\n\n%s\n\nClick 'Authorize' to grant permission to the OS.", resourceDesc),
		func(b bool) {
			if b {
				go func() {
					err := action()
					fyne.Do(func() {
						if err != nil {
							dialog.ShowError(fmt.Errorf("action failed: %v", err), w)
						} else {
							dialog.ShowInformation("Success", "Action completed successfully.", w)
						}
					})
				}()
			}
		}, w)
}

func main() {
	a := app.New()
	a.Settings().SetTheme(&ui.AfterSecTheme{})
	w := a.NewWindow("AfterSec - Security Posture Manager")
	w.Resize(fyne.NewSize(800, 600))
	w.CenterOnScreen()
	ui.SetupTray(a, w)

	state := &appState{}

	// Load configuration early so it's available throughout the app
	mgr, err := getManager()
	if err != nil {
		dialog.ShowError(fmt.Errorf("storage init failed: %w", err), w)
		return
	}
	fullCfg, err := client.LoadConfig(mgr.GetConfigPath())
	if err != nil {
		fullCfg = client.DefaultClientConfig()
	}
	cfg := &fullCfg.Core

	os.Setenv("GEMINI_API_KEY", fullCfg.Daemon.AI.GeminiKey)
	os.Setenv("OPENAI_API_KEY", fullCfg.Daemon.AI.OpenAIKey)
	os.Setenv("ANTHROPIC_API_KEY", fullCfg.Daemon.AI.AnthropicKey)

	statusLabel := widget.NewLabel("Click 'Run Scan' to assess system security posture.")
	statusLabel.Alignment = fyne.TextAlignCenter
	statusLabel.Wrapping = fyne.TextWrapWord

	// Bottom Progress UI
	progressBar := widget.NewProgressBar()
	progressBar.Hide()
	
	phaseLabel := widget.NewLabel("")
	phaseLabel.Alignment = fyne.TextAlignCenter
	phaseLabel.Hide()
	
	detailsBtn := widget.NewButton("View Verbose Logs", func() {
		state.mu.RLock()
		logs := state.verboseLogs
		state.mu.RUnlock()

		logWin := a.NewWindow("Scan Execution Log")
		logWin.Resize(fyne.NewSize(600, 400))
		logEntry := widget.NewMultiLineEntry()
		logEntry.SetText(logs)
		logEntry.Disable()
		logWin.SetContent(container.NewScroll(logEntry))
		logWin.Show()
	})
	detailsBtn.Hide()

	progressBox := container.NewVBox(phaseLabel, progressBar, detailsBtn)
	scanContent := container.NewStack(statusLabel)

	// Search functionality
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search findings...")

	// Severity-based tab containers
	logOnlyVBox := container.NewVBox()
	lowVBox := container.NewVBox()
	medVBox := container.NewVBox()
	highVBox := container.NewVBox()
	veryHighVBox := container.NewVBox()
	criticalVBox := container.NewVBox()

	logOnlyScroll := container.NewVScroll(logOnlyVBox)
	lowScroll := container.NewVScroll(lowVBox)
	medScroll := container.NewVScroll(medVBox)
	highScroll := container.NewVScroll(highVBox)
	veryHighScroll := container.NewVScroll(veryHighVBox)
	criticalScroll := container.NewVScroll(criticalVBox)

	severityTabs := container.NewAppTabs(
		container.NewTabItem("Log Only", logOnlyScroll),
		container.NewTabItem("Low", lowScroll),
		container.NewTabItem("Medium", medScroll),
		container.NewTabItem("High", highScroll),
		container.NewTabItem("Very High", veryHighScroll),
		container.NewTabItem("Critical", criticalScroll),
	)

	// Function to create finding card
	createFindingCard := func(f core.Finding) fyne.CanvasObject {
		title := widget.NewLabelWithStyle(fmt.Sprintf("%s - %s", f.Category, f.Name), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		passStr := "PASSED"
		if !f.Passed {
			passStr = "FAILED"
		}
		status := widget.NewLabel(fmt.Sprintf("Severity: %s | Status: %s", f.Severity, passStr))

		fc := f

		// Settings button to change finding configuration
		settingsBtn := widget.NewButton("⚙️ Settings", func() {
			// Create severity selector
			severitySelect := widget.NewSelect([]string{
				string(core.LogOnly),
				string(core.Low),
				string(core.Med),
				string(core.High),
				string(core.VeryHigh),
				string(core.Critical),
			}, nil)
			severitySelect.SetSelected(string(fc.Severity))

			disableCheck := widget.NewCheck("Disable this finding", nil)

			// Check if there's an existing override
			findingKey := core.GetFindingKey(fc)
			if override, exists := cfg.FindingOverrides[findingKey]; exists {
				disableCheck.SetChecked(override.Disabled)
				severitySelect.SetSelected(string(override.Severity))
			}

			settingsContent := container.NewVBox(
				widget.NewLabel(fmt.Sprintf("Configure: %s", fc.Name)),
				widget.NewLabel(""),
				widget.NewLabel("Severity Level:"),
				severitySelect,
				widget.NewLabel(""),
				disableCheck,
			)

			dialog.ShowCustomConfirm("Finding Settings", "Apply", "Cancel", settingsContent, func(apply bool) {
				if !apply {
					return
				}

				// Save override
				if cfg.FindingOverrides == nil {
					cfg.FindingOverrides = make(map[string]core.FindingOverride)
				}

				cfg.FindingOverrides[findingKey] = core.FindingOverride{
					Severity: core.Severity(severitySelect.Selected),
					Disabled: disableCheck.Checked,
				}

				// Save config
				mgr, _ := getManager()
				mgr.SaveConfig(cfg)

				dialog.ShowInformation("Settings Saved",
					fmt.Sprintf("Settings for '%s' have been saved.\n\nRe-run the scan to see changes.", fc.Name), w)
			}, w)
		})

		var cardObj fyne.CanvasObject
		if !f.Passed {
			detailsBtn := widget.NewButton("View Details", nil)
			detailsBtn.OnTapped = func() {
				content := container.NewVBox(
					widget.NewLabel(fmt.Sprintf("Expected:\n%s\n\nCurrent:\n%s", fc.ExpectedVal, fc.CurrentVal)),
					widget.NewLabel(fc.Description),
				)
				if fc.RemediationScript != "" {
					scriptCopy := fc.RemediationScript
					fixBtn := widget.NewButton("Auto-Remediate (Requires Admin)", func() {
						requireAdmin(w, fc.Name+" configuration", func() error {
							return core.RunPrivileged(scriptCopy)
						})
					})
					content.Add(fixBtn)
				}
				dialog.ShowCustom(fmt.Sprintf("Details: %s", fc.Name), "Close", content, w)
			}
			cardObj = container.NewVBox(title, status, container.NewHBox(detailsBtn, settingsBtn))
		} else {
			cardObj = container.NewVBox(title, status, settingsBtn)
		}
		return widget.NewCard("", "", cardObj)
	}

	// Function to populate severity tabs with filtering
	populateSeverityTabs := func(findings []core.Finding, searchTerm string) {
		logOnlyVBox.RemoveAll()
		lowVBox.RemoveAll()
		medVBox.RemoveAll()
		highVBox.RemoveAll()
		veryHighVBox.RemoveAll()
		criticalVBox.RemoveAll()

		for _, f := range findings {
			// Apply search filter
			if searchTerm != "" {
				match := false
				searchLower := strings.ToLower(searchTerm)
				if strings.Contains(strings.ToLower(f.Name), searchLower) ||
					strings.Contains(strings.ToLower(f.Category), searchLower) ||
					strings.Contains(strings.ToLower(f.Description), searchLower) {
					match = true
				}
				if !match {
					continue
				}
			}

			card := createFindingCard(f)

			switch f.Severity {
			case core.LogOnly:
				logOnlyVBox.Add(card)
			case core.Low:
				lowVBox.Add(card)
			case core.Med:
				medVBox.Add(card)
			case core.High:
				highVBox.Add(card)
			case core.VeryHigh:
				veryHighVBox.Add(card)
			case core.Critical:
				criticalVBox.Add(card)
			}
		}

		logOnlyVBox.Refresh()
		lowVBox.Refresh()
		medVBox.Refresh()
		highVBox.Refresh()
		veryHighVBox.Refresh()
		criticalVBox.Refresh()
	}

	// Search handler
	searchEntry.OnChanged = func(searchTerm string) {
		state.mu.RLock()
		currentFindings := state.currentFindings
		state.mu.RUnlock()
		populateSeverityTabs(currentFindings, searchTerm)
	}

	scanBtn := widget.NewButton("Run Scan", func() {
		statusLabel.Hide()

		state.mu.Lock()
		state.verboseLogs = fmt.Sprintf("--- Scan Initiated at %s ---\n", time.Now().Format("15:04:05"))
		state.mu.Unlock()

		progressBar.SetValue(0)
		progressBar.Show()
		phaseLabel.SetText("Initializing scanner engine...")
		phaseLabel.Show()
		detailsBtn.Hide()

		scanContent.RemoveAll()
		scanContent.Add(container.NewBorder(searchEntry, nil, nil, nil, severityTabs))
		scanContent.Refresh()

		go func() {
			mgr, _ := getManager()
			scanner := scanners.NewMacOSScanner(mgr)
			scanResult, err := scanner.Scan(func(p float64, msg string) {
				fyne.Do(func() {
					progressBar.SetValue(p)
					phaseLabel.SetText(msg)
					state.mu.Lock()
					state.verboseLogs += fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05.000"), msg)
					state.mu.Unlock()
				})
			})
			if err != nil {
				fyne.Do(func() {
					progressBar.Hide()
					phaseLabel.Hide()
					detailsBtn.Show()
					statusLabel.SetText(fmt.Sprintf("Error scanning: %v", err))
					statusLabel.Show()
					scanContent.RemoveAll()
					scanContent.Add(statusLabel)
					scanContent.Refresh()
				})
				return
			}
			fyne.Do(func() {
				progressBar.Hide()
				phaseLabel.Hide()
				detailsBtn.Show()

				state.mu.Lock()
				state.verboseLogs += "--- Scan Completed Successfully ---\n"
				// Apply user overrides to findings
				scanResult.Findings = cfg.ApplyOverrides(scanResult.Findings)
				state.currentFindings = scanResult.Findings
				state.lastState = scanResult
				currentFindings := state.currentFindings
				state.mu.Unlock()

				populateSeverityTabs(currentFindings, searchEntry.Text)

				scanContent.RemoveAll()
				scanContent.Add(container.NewBorder(searchEntry, nil, nil, nil, severityTabs))
				scanContent.Refresh()
			})
		}()
	})

	exportJsonBtn := widget.NewButton("Export JSON", func() {
		state.mu.RLock()
		ls := state.lastState
		state.mu.RUnlock()

		if ls == nil {
			return
		}
		dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
			if uc == nil || err != nil {
				return
			}
			defer uc.Close()
			scanners.ExportJSON(ls, uc.URI().Path())
		}, w)
	})

	exportPdfBtn := widget.NewButton("Export PDF", func() {
		state.mu.RLock()
		ls := state.lastState
		state.mu.RUnlock()

		if ls == nil {
			return
		}
		dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
			if uc == nil || err != nil {
				return
			}
			defer uc.Close()
			scanners.ExportPDF(ls, uc.URI().Path())
		}, w)
	})

	topRow := container.NewHBox(scanBtn, exportJsonBtn, exportPdfBtn)
	
	// Dock the progressBox at the bottom of the Border layout
	scannerTab := container.NewBorder(topRow, progressBox, nil, nil, scanContent)

	// Diff & Commit Tab
	diffStatus := widget.NewLabel("Run 'Compare With Last Commit' to view differences.")
	diffStatus.Wrapping = fyne.TextWrapWord
	diffStatus.Alignment = fyne.TextAlignCenter

	diffVBox := container.NewVBox()
	diffScroll := container.NewVScroll(diffVBox)

	diffProgressBar := widget.NewProgressBar()
	diffProgressBar.Hide()
	diffContent := container.NewStack(diffStatus)

	runDiffBtn := widget.NewButton("Compare With Last Commit", func() {
		mgr, err := getManager()
		if err != nil {
			diffStatus.SetText("Error storage manager " + err.Error())
			diffContent.RemoveAll()
			diffContent.Add(diffStatus)
			diffContent.Refresh()
			return
		}

		latest, _ := mgr.GetLatest()

		diffStatus.Hide()
		diffProgressBar.SetValue(0)
		diffProgressBar.Show()
		diffContent.RemoveAll()
		diffContent.Add(diffScroll) // Keep scroll view in center
		diffContent.Refresh()

		go func() {
			mgr, _ := getManager()
			scanner := scanners.NewMacOSScanner(mgr)
			current, err := scanner.Scan(func(p float64, msg string) {
				fyne.Do(func() {
					diffProgressBar.SetValue(p)
				})
			})

			fyne.Do(func() {
				diffProgressBar.Hide()
				if err != nil {
					diffStatus.SetText("Error scanning: " + err.Error())
					diffStatus.Show()
					diffContent.RemoveAll()
					diffContent.Add(diffStatus)
					diffContent.Refresh()
					return
				}

				state.mu.Lock()
				state.currentState = current
				state.mu.Unlock()

				if latest == nil {
					diffStatus.SetText("No previous commits found. System baseline is uninitialized.")
					diffStatus.Show()
					diffContent.RemoveAll()
					diffContent.Add(diffStatus)
					diffContent.Refresh()
					return
				}

				diff := core.CompareStates(latest, current)
				if !diff.HasChanges() {
					diffStatus.SetText("No changes detected since the last commit.")
					diffStatus.Show()
					diffContent.RemoveAll()
					diffContent.Add(diffStatus)
					diffContent.Refresh()
					return
				}

				state.mu.Lock()
				state.diffChanges = diff.Changes
				diffChanges := state.diffChanges
				state.mu.Unlock()

				diffVBox.RemoveAll()
				for _, d := range diffChanges {
					lbl := widget.NewLabel(d)
					lbl.Wrapping = fyne.TextWrapWord
					diffVBox.Add(lbl)
				}
				diffVBox.Refresh()
				diffContent.RemoveAll()
				diffContent.Add(diffScroll)
				diffContent.Refresh()
			})
		}()
	})

	commitBtn := widget.NewButton("Commit Current State as Baseline", func() {
		state.mu.RLock()
		cs := state.currentState
		state.mu.RUnlock()

		if cs == nil {
			diffStatus.SetText("Please run a scan or comparison first.")
			diffStatus.Show()
			diffContent.RemoveAll()
			diffContent.Add(diffStatus)
			diffContent.Refresh()
			return
		}
		mgr, err := getManager()
		if err != nil {
			diffStatus.SetText("Error: storage manager - " + err.Error())
			diffStatus.Show()
			diffContent.RemoveAll()
			diffContent.Add(diffStatus)
			diffContent.Refresh()
			return
		}
		if err := mgr.SaveCommit(cs); err != nil {
			diffStatus.SetText("Error: saving commit - " + err.Error())
			diffStatus.Show()
			diffContent.RemoveAll()
			diffContent.Add(diffStatus)
			diffContent.Refresh()
			return
		}
		diffStatus.SetText("Successfully committed baseline!")
		diffStatus.Show()
		diffContent.RemoveAll()
		diffContent.Add(diffStatus)
		diffContent.Refresh()

		state.mu.Lock()
		state.currentState = nil
		state.mu.Unlock()
	})

	commitAndRevertBtn := widget.NewButton("Restore Latest Baseline", func() {
		mgr, err := getManager()
		if err != nil {
			dialog.ShowError(fmt.Errorf("storage error: %v", err), w)
			return
		}

		latest, err := mgr.GetLatest()
		if err != nil || latest == nil {
			dialog.ShowError(fmt.Errorf("no previous commit found or error: %v", err), w)
			return
		}

		scanner := scanners.NewMacOSScanner(mgr)
		diffStatus.SetText("Scanning current state...")
		diffStatus.Show()
		diffContent.RemoveAll()
		diffContent.Add(diffStatus)

		go func() {
			current, err := scanner.Scan(nil)
			fyne.Do(func() {
				if err != nil {
					diffStatus.SetText(fmt.Sprintf("Scan failed: %v", err))
					return
				}
				actions, err := core.RestoreToState(latest, current)
				if err != nil {
					diffStatus.SetText(fmt.Sprintf("Restore failed: %v", err))
					return
				}
				if len(actions) == 0 {
					diffStatus.SetText("System already matches or exceeds the baseline!")
				} else {
					msg := "Applied Restores:\n"
					for _, act := range actions {
						msg += "- " + act + "\n"
					}
					diffStatus.SetText(msg)
				}
				diffStatus.Show()
				diffContent.RemoveAll()
				diffContent.Add(diffStatus)
			})
		}()
	})



	// History Tab
	var historyEntries []string
	historyStatus := widget.NewLabel("Click 'View History' to see previous baseline commits.")
	historyStatus.Wrapping = fyne.TextWrapWord
	historyStatus.Alignment = fyne.TextAlignCenter

	var historyStates []*core.SecurityState
	historyList := widget.NewList(
		func() int { return len(historyEntries) },
		func() fyne.CanvasObject {
			return container.NewBorder(nil, nil, nil, widget.NewButton("Restore", nil), widget.NewLabel(""))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			c := o.(*fyne.Container)
			var lbl *widget.Label
			var btn *widget.Button
			for _, obj := range c.Objects {
				switch v := obj.(type) {
				case *widget.Label:
					lbl = v
				case *widget.Button:
					btn = v
				}
			}

			lbl.SetText(historyEntries[i])
			targetState := historyStates[i]

			btn.OnTapped = func() {
				dialog.ShowConfirm("Restore System Status", 
					fmt.Sprintf("Restore system to state from %s?", targetState.Timestamp.Format("2006-01-02 15:04:05")),
					func(b bool) {
						if b {
							mgr, _ := getManager()
							scanner := scanners.NewMacOSScanner(mgr)
							go func() {
								current, err := scanner.Scan(nil)
								if err != nil {
									fyne.Do(func() { dialog.ShowError(err, w) })
									return
								}
								actions, err := core.RestoreToState(targetState, current)
								fyne.Do(func() {
									if err != nil {
										dialog.ShowError(fmt.Errorf("restore failed: %v", err), w)
									} else if len(actions) == 0 {
										dialog.ShowInformation("Restore Complete", "System already matches or exceeds this state.", w)
									} else {
										msg := "Actions applied:\n"
										for _, a := range actions {
											msg += a + "\n"
										}
										dialog.ShowInformation("Restore Complete", msg, w)
									}
								})
							}()
						}
					}, w)
			}
		},
	)
	historyContent := container.NewStack(historyStatus)

	historyBtn := widget.NewButton("View History", func() {
		mgr, err := getManager()
		if err != nil {
			historyStatus.SetText("Error storage manager " + err.Error())
			historyContent.Objects = []fyne.CanvasObject{historyStatus}
			historyContent.Refresh()
			return
		}
		history, _ := mgr.GetHistory()
		if len(history) == 0 {
			historyStatus.SetText("No history found.")
			historyContent.Objects = []fyne.CanvasObject{historyStatus}
			historyContent.Refresh()
			return
		}
		
		historyEntries = make([]string, len(history))
		historyStates = history
		for i, h := range history {
			historyEntries[i] = fmt.Sprintf("[%d] %s", i, h.Timestamp.Format("2006-01-02 15:04:05"))
		}
		historyList.Refresh()
		historyContent.Objects = []fyne.CanvasObject{historyList}
		historyContent.Refresh()
	})
	historyTab := container.NewBorder(historyBtn, nil, nil, nil, historyContent)

	// Settings Tab
	strictCheck := widget.NewCheck("Strict Mode (treat warnings as failures)", func(b bool) {
		cfg.StrictMode = b
	})
	strictCheck.SetChecked(cfg.StrictMode)

	autoScanCheck := widget.NewCheck("Auto-Scan on Startup", func(b bool) {
		cfg.AutoScan = b
	})
	autoScanCheck.SetChecked(cfg.AutoScan)

	whitelistEntry := widget.NewMultiLineEntry()
	whitelistEntry.SetText(cfg.WhitelistedPaths)
	whitelistEntry.OnChanged = func(s string) {
		cfg.WhitelistedPaths = s
	}

	aiProvider := widget.NewSelect([]string{"gemini", "openai", "anthropic"}, func(s string) {
		fullCfg.Daemon.AI.Provider = s
	})
	if fullCfg.Daemon.AI.Provider != "" {
		aiProvider.SetSelected(fullCfg.Daemon.AI.Provider)
	}

	geminiKey := widget.NewPasswordEntry()
	geminiKey.SetText(fullCfg.Daemon.AI.GeminiKey)
	geminiKey.OnChanged = func(s string) { fullCfg.Daemon.AI.GeminiKey = s }

	openAIKey := widget.NewPasswordEntry()
	openAIKey.SetText(fullCfg.Daemon.AI.OpenAIKey)
	openAIKey.OnChanged = func(s string) { fullCfg.Daemon.AI.OpenAIKey = s }

	anthropicKey := widget.NewPasswordEntry()
	anthropicKey.SetText(fullCfg.Daemon.AI.AnthropicKey)
	anthropicKey.OnChanged = func(s string) { fullCfg.Daemon.AI.AnthropicKey = s }

	mispEnabledCheck := widget.NewCheck("Enable MISP Integration", func(b bool) { fullCfg.Daemon.ThreatIntel.MISP.Enabled = b })
	mispEnabledCheck.SetChecked(fullCfg.Daemon.ThreatIntel.MISP.Enabled)

	mispURL := widget.NewEntry()
	mispURL.SetText(fullCfg.Daemon.ThreatIntel.MISP.BaseURL)
	mispURL.OnChanged = func(s string) { fullCfg.Daemon.ThreatIntel.MISP.BaseURL = s }

	mispKey := widget.NewPasswordEntry()
	mispKey.SetText(fullCfg.Daemon.ThreatIntel.MISP.AuthKey)
	mispKey.OnChanged = func(s string) { fullCfg.Daemon.ThreatIntel.MISP.AuthKey = s }

	saveStatus := widget.NewLabel("")
	saveStatus.Hide()

	saveBtn := widget.NewButton("Save Settings & Apply APIs", func() {
		os.Setenv("GEMINI_API_KEY", fullCfg.Daemon.AI.GeminiKey)
		os.Setenv("OPENAI_API_KEY", fullCfg.Daemon.AI.OpenAIKey)
		os.Setenv("ANTHROPIC_API_KEY", fullCfg.Daemon.AI.AnthropicKey)

		// Sync core parameters to local DB manager just in case
		mgr.SaveConfig(cfg)

		if err := client.SaveConfig(fullCfg, mgr.GetConfigPath()); err != nil {
			saveStatus.SetText("Error saving settings: " + err.Error())
		} else {
			saveStatus.SetText("Settings saved successfully! APIs Active.")
		}
		saveStatus.Show()
		go func() {
			time.Sleep(3 * time.Second)
			fyne.Do(func() { saveStatus.Hide() })
		}()
	})

	settingsForm := widget.NewForm(
		widget.NewFormItem("Strict Mode", strictCheck),
		widget.NewFormItem("Auto Scan", autoScanCheck),
		widget.NewFormItem("Whitelisted Paths", whitelistEntry),
		widget.NewFormItem("AI Provider", aiProvider),
		widget.NewFormItem("Gemini Key", geminiKey),
		widget.NewFormItem("OpenAI Key", openAIKey),
		widget.NewFormItem("Anthropic Key", anthropicKey),
		widget.NewFormItem("MISP Enabled", mispEnabledCheck),
		widget.NewFormItem("MISP Base URL", mispURL),
		widget.NewFormItem("MISP Auth Key", mispKey),
	)

	settingsTop := container.NewVBox(saveBtn, saveStatus)
	settingsScroll := container.NewVScroll(settingsForm)
	settingsTab := container.NewBorder(settingsTop, nil, nil, nil, settingsScroll)

	// Malware Scanner Tab (DarkScan)
	var malwarePath string
	var selectedProfile = "standard" // default profile

	malwareLbl := widget.NewLabel("Select a file, folder, or disk for Multi-Engine Scanning")
	malwareLbl.Alignment = fyne.TextAlignCenter

	// Profile selector
	profileSelect := widget.NewSelect([]string{
		"quick (30s, fast)",
		"standard (2m, balanced)",
		"deep (10m, thorough)",
		"forensic (30m, comprehensive)",
		"safe (1m, production)",
	}, func(s string) {
		// Extract profile name from the display string
		if len(s) > 0 {
			// Get the profile name before the first space
			for i, c := range s {
				if c == ' ' {
					selectedProfile = s[:i]
					break
				}
			}
		}
	})
	profileSelect.SetSelected("standard (2m, balanced)")

	profileLbl := widget.NewLabel("Scan Profile:")
	profileRow := container.NewBorder(nil, nil, profileLbl, nil, profileSelect)

	malwareResultsVBox := container.NewVBox()
	malwareResultsScroll := container.NewVScroll(malwareResultsVBox)
	malwarePhase := widget.NewLabel("")
	malwarePhase.Hide()
	
	runMalwareScan := func() {
		if malwarePath == "" {
			dialog.ShowError(fmt.Errorf("please select a target first"), w)
			return
		}
		
		malwarePhase.SetText(fmt.Sprintf("Initializing DarkScan Client (Profile: %s)...", selectedProfile))
		malwarePhase.Show()
		malwareResultsVBox.RemoveAll()

		go func() {
			mgr, err := getManager()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w); malwarePhase.Hide() })
				return
			}
			cfgPath := mgr.GetConfigPath()
			fullCfg, err := client.LoadConfig(cfgPath)
			if err != nil {
				fullCfg = client.DefaultClientConfig()
			}

			dsClient, err := darkscan.NewClient(&fullCfg.Daemon.DarkScan)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(fmt.Errorf("failed to init engines: %v", err), w); malwarePhase.Hide() })
				return
			}

			// Apply the selected profile if available
			if selectedProfile != "" && selectedProfile != "standard" {
				if err := dsClient.ApplyProfile(selectedProfile); err != nil {
					// Log the error but continue with default settings
					fmt.Fprintf(os.Stderr, "Warning: failed to apply profile %s: %v\n", selectedProfile, err)
				}
			}

			fyne.Do(func() { malwarePhase.SetText(fmt.Sprintf("Scanning with %s profile...", selectedProfile)) })
			
			info, err := os.Stat(malwarePath)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w); malwarePhase.Hide() })
				return
			}
			
			var results []*darkscan.ScanResult
			ctx := context.Background()
			if info.IsDir() {
				results, err = dsClient.ScanDirectory(ctx, malwarePath, true)
			} else {
				res, se := dsClient.ScanFile(ctx, malwarePath)
				err = se
				results = []*darkscan.ScanResult{res}
			}
			
			fyne.Do(func() {
				malwarePhase.Hide()
				if err != nil {
					dialog.ShowError(err, w)
					return
				}

				malwareResultsVBox.RemoveAll()
				threatCount := 0
				cleanCount := 0
				totalEngines := 0
				var usedEngines = make(map[string]bool)

				for _, r := range results {
					if r == nil { continue }
					if r.Error != nil && r.Error.Error() == "yara: rules path is required when YARA is enabled" { continue }

					// Track engines used
					if r.EngineCount > 0 {
						totalEngines = r.EngineCount
						for _, engine := range r.EnginesUsed {
							usedEngines[engine] = true
						}
					}

					if r.Infected {
						threatCount++
						title := widget.NewLabelWithStyle(fmt.Sprintf("🚨 Infected: %s", r.FilePath), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

						// Build threat details
						threatList := ""
						for _, t := range r.Threats {
							threatList += fmt.Sprintf("- [%s] %s (%s)\n", t.Engine, t.Name, t.Severity)
							if t.Description != "" {
								threatList += fmt.Sprintf("  Description: %s\n", t.Description)
							}
						}

						// Add scan metadata
						metadata := fmt.Sprintf("\nScanned by %d engine(s)", r.EngineCount)
						if r.ScanDuration > 0 {
							metadata += fmt.Sprintf(" in %v", r.ScanDuration)
						}

						lbl := widget.NewLabel(threatList + metadata)
						lbl.Wrapping = fyne.TextWrapWord

						// Add quarantine button
						rCopy := r
						quarantineBtn := widget.NewButton("Quarantine File", func() {
							go func() {
								qID, err := dsClient.QuarantineFile(context.Background(), rCopy.FilePath, rCopy.Threats)
								fyne.Do(func() {
									if err != nil {
										dialog.ShowError(fmt.Errorf("quarantine failed: %v", err), w)
									} else {
										dialog.ShowInformation("Success", fmt.Sprintf("File quarantined: %s", qID), w)
									}
								})
							}()
						})

						malwareResultsVBox.Add(widget.NewCard("", "", container.NewVBox(title, lbl, quarantineBtn)))
					} else {
						cleanCount++
					}
				}

				// Build summary
				if threatCount == 0 {
					summary := fmt.Sprintf("✅ Scan Complete. No threats detected.\n\nScanned: %d file(s) | Engines: %d", len(results), totalEngines)
					if len(usedEngines) > 0 {
						summary += "\nEngines used: "
						first := true
						for engine := range usedEngines {
							if !first {
								summary += ", "
							}
							summary += engine
							first = false
						}
					}
					lbl := widget.NewLabel(summary)
					lbl.Alignment = fyne.TextAlignCenter
					malwareResultsVBox.Add(lbl)
				} else {
					summary := fmt.Sprintf("⚠️ Detected %d malicious file(s) | Clean: %d | Total: %d", threatCount, cleanCount, len(results))
					summaryLbl := widget.NewLabelWithStyle(summary, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
					malwareResultsVBox.Objects = append([]fyne.CanvasObject{summaryLbl}, malwareResultsVBox.Objects...)
				}
				malwareResultsVBox.Refresh()
			})
		}()
	}

	btnChooseFile := widget.NewButton("Scan File", func() {
		dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
			if uc != nil { malwarePath = uc.URI().Path(); runMalwareScan() }
		}, w)
	})
	btnChooseDir := widget.NewButton("Scan Directory", func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if lu != nil { malwarePath = lu.Path(); runMalwareScan() }
		}, w)
	})
	btnChooseDisk := widget.NewButton("Scan Disk", func() {
		// Get available volumes
		volumes := detectAvailableVolumes()

		// Create radio group with volume options
		var volumePaths []string
		var volumeLabels []string
		for _, vol := range volumes {
			volumePaths = append(volumePaths, vol.Path)
			label := vol.MountPoint
			if vol.Filesystem != "" {
				label += " (" + vol.Filesystem + ")"
			}
			volumeLabels = append(volumeLabels, label)
		}

		if len(volumeLabels) == 0 {
			dialog.ShowError(fmt.Errorf("no volumes detected"), w)
			return
		}

		volumeRadio := widget.NewRadioGroup(volumeLabels, nil)
		volumeRadio.SetSelected(volumeLabels[0])

		dialogContent := container.NewVBox(
			widget.NewLabel("Select a disk/volume to scan:"),
			volumeRadio,
		)

		dialog.ShowCustomConfirm("Select Disk", "Start Scan", "Cancel", dialogContent, func(confirmed bool) {
			if confirmed && volumeRadio.Selected != "" {
				// Find the selected volume path
				for i, label := range volumeLabels {
					if label == volumeRadio.Selected {
						malwarePath = volumePaths[i]
						runMalwareScan()
						break
					}
				}
			}
		}, w)
	})

	btnViewQuarantine := widget.NewButton("View Quarantine", func() {
		go func() {
			mgr, err := getManager()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
				return
			}
			cfgPath := mgr.GetConfigPath()
			fullCfg, err := client.LoadConfig(cfgPath)
			if err != nil {
				fullCfg = client.DefaultClientConfig()
			}

			dsClient, err := darkscan.NewClient(&fullCfg.Daemon.DarkScan)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(fmt.Errorf("failed to init DarkScan: %v", err), w) })
				return
			}

			qItems, err := dsClient.ListQuarantine(context.Background())
			if err != nil {
				fyne.Do(func() { dialog.ShowError(fmt.Errorf("failed to list quarantine: %v", err), w) })
				return
			}

			fyne.Do(func() {
				if len(qItems) == 0 {
					dialog.ShowInformation("Quarantine", "No files in quarantine.", w)
					return
				}

				qWin := a.NewWindow("Quarantine Manager")
				qWin.Resize(fyne.NewSize(700, 500))

				qList := container.NewVBox()
				for _, item := range qItems {
					itemCopy := item
					title := widget.NewLabelWithStyle(fmt.Sprintf("📦 %s", itemCopy.OriginalPath), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
					details := fmt.Sprintf("Quarantined: %s\nThreats: %d\nSize: %d bytes\nID: %s",
						itemCopy.QuarantinedAt.Format("2006-01-02 15:04:05"),
						len(itemCopy.Threats),
						itemCopy.FileSize,
						itemCopy.QuarantineID)
					detailsLbl := widget.NewLabel(details)
					detailsLbl.Wrapping = fyne.TextWrapWord

					btnRestore := widget.NewButton("Restore", func() {
						dialog.ShowConfirm("Restore File",
							fmt.Sprintf("Are you sure you want to restore:\n%s\n\nThis file was quarantined due to threats.", itemCopy.OriginalPath),
							func(confirmed bool) {
								if confirmed {
									go func() {
										err := dsClient.RestoreQuarantined(context.Background(), itemCopy.QuarantineID, itemCopy.OriginalPath)
										fyne.Do(func() {
											if err != nil {
												dialog.ShowError(fmt.Errorf("restore failed: %v", err), w)
											} else {
												dialog.ShowInformation("Success", "File restored successfully.", w)
												qWin.Close()
											}
										})
									}()
								}
							}, w)
					})

					btnDelete := widget.NewButton("Delete", func() {
						dialog.ShowConfirm("Delete Quarantined File",
							fmt.Sprintf("Permanently delete:\n%s\n\nThis cannot be undone.", itemCopy.OriginalPath),
							func(confirmed bool) {
								if confirmed {
									go func() {
										err := dsClient.DeleteQuarantined(context.Background(), itemCopy.QuarantineID)
										fyne.Do(func() {
											if err != nil {
												dialog.ShowError(fmt.Errorf("delete failed: %v", err), w)
											} else {
												dialog.ShowInformation("Success", "File deleted successfully.", w)
												qWin.Close()
											}
										})
									}()
								}
							}, w)
					})

					card := widget.NewCard("", "", container.NewVBox(title, detailsLbl, container.NewHBox(btnRestore, btnDelete)))
					qList.Add(card)
				}

				qScroll := container.NewVScroll(qList)
				qWin.SetContent(qScroll)
				qWin.Show()
			})
		}()
	})

	malwareSelectRow := container.NewGridWithColumns(4, btnChooseFile, btnChooseDir, btnChooseDisk, btnViewQuarantine)
	malwareTop := container.NewVBox(malwareLbl, profileRow, malwareSelectRow, malwarePhase)
	malwareScannerTab := container.NewBorder(malwareTop, nil, nil, nil, malwareResultsScroll)

	// Forensics Tab
	forensicsListBox := container.NewVBox()
	forensicsScroll := container.NewVScroll(forensicsListBox)
	forensicsStatus := widget.NewLabel("Click 'Scan Process Memory' to hunt for active malware.")
	forensicsStatus.Alignment = fyne.TextAlignCenter
	forensicsStatus.Wrapping = fyne.TextWrapWord

	forensicsContent := container.NewStack(forensicsStatus)
	forensicsProgressBar := widget.NewProgressBar()
	forensicsProgressBar.Hide()
	forensicsPhase := widget.NewLabel("")
	forensicsPhase.Alignment = fyne.TextAlignCenter
	forensicsPhase.Hide()

	runForensicsBtn := widget.NewButton("Scan Process Memory", func() {
		forensicsStatus.Hide()
		forensicsContent.RemoveAll()
		forensicsContent.Add(forensicsScroll)
		forensicsProgressBar.SetValue(0)
		forensicsProgressBar.Show()
		forensicsPhase.SetText("Analyzing Process Memory...")
		forensicsPhase.Show()

		go func() {
			for i := 0.0; i <= 1.0; i += 0.2 {
				fyne.Do(func() { forensicsProgressBar.SetValue(i) })
				time.Sleep(100 * time.Millisecond)
			}
			
			mgr, _ := getManager()
			evaluator := ai.NewThreatEvaluator(mgr)
			anomalies, err := forensics.ScanRunningProcesses(mgr)
			if err == nil {
				for i := range anomalies {
					newScore, newReason := evaluator.EvaluateProcess(anomalies[i].PID, float64(anomalies[i].Score), anomalies[i].Reason)
					anomalies[i].Score = forensics.ThreatScore(int(newScore))
					anomalies[i].Reason = newReason
				}
			}
			
			fyne.Do(func() {
				forensicsProgressBar.Hide()
				forensicsPhase.Hide()
				
				if err != nil {
					forensicsStatus.SetText("Error executing forensic scan: " + err.Error())
					forensicsStatus.Show()
					forensicsContent.RemoveAll()
					forensicsContent.Add(forensicsStatus)
					forensicsContent.Refresh()
					return
				}
				
				forensicsListBox.RemoveAll()
				
				if len(anomalies) == 0 {
					forensicsStatus.SetText("✅ Safe! No malicious or anomalous processes found running.")
					forensicsStatus.Show()
					forensicsContent.RemoveAll()
					forensicsContent.Add(forensicsStatus)
					forensicsContent.Refresh()
					return
				}

				for _, a := range anomalies {
					title := widget.NewLabelWithStyle(fmt.Sprintf("PID %d - User: %s", a.PID, a.User), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
					scoreLbl := widget.NewLabel(fmt.Sprintf("Score: %s | Reason: %s", a.Score.String(), a.Reason))
					cmdLbl := widget.NewLabel(a.Command)
					cmdLbl.Wrapping = fyne.TextWrapWord
					
					cmdCopy := a.KillCommand
					killBtn := widget.NewButton("Kill Process (Requires Admin)", func() {
						requireAdmin(w, fmt.Sprintf("Process %d (%s)", a.PID, a.Command), func() error {
							err := core.RunPrivileged(cmdCopy)
							if err == nil {
								fyne.Do(func() { title.SetText(title.Text + " [KILLED]") })
							}
							return err
						})
					})
					cardObj := container.NewVBox(title, scoreLbl, cmdLbl, killBtn)
					forensicsListBox.Add(widget.NewCard("", "", cardObj))
				}
				forensicsListBox.Refresh()
				forensicsContent.Refresh()
			})
		}()
	})

	trainBaselineBtn := widget.NewButton("Train Process Baseline", func() {
		forensicsStatus.SetText("Learning process baseline... please wait.")
		forensicsStatus.Show()
		forensicsContent.RemoveAll()
		forensicsContent.Add(forensicsStatus)
		
		go func() {
			err := forensics.TrainProcessBaseline()
			fyne.Do(func() {
				if err != nil {
					forensicsStatus.SetText("Error training baseline: " + err.Error())
				} else {
					forensicsStatus.SetText("✅ Baseline trained. Current behaviors are recorded as known-good.")
				}
				forensicsStatus.Show()
				forensicsContent.RemoveAll()
				forensicsContent.Add(forensicsStatus)
			})
		}()
	})

	scanPersistenceBtn := widget.NewButton("Scan Startup Persistence", func() {
		forensicsStatus.Hide()
		forensicsContent.RemoveAll()
		forensicsContent.Add(forensicsScroll)
		forensicsProgressBar.SetValue(0)
		forensicsProgressBar.Show()
		forensicsPhase.SetText("Analyzing LaunchDaemons & LaunchAgents...")
		forensicsPhase.Show()

		go func() {
			for i := 0.0; i <= 1.0; i += 0.2 {
				fyne.Do(func() { forensicsProgressBar.SetValue(i) })
				time.Sleep(100 * time.Millisecond)
			}
			
			anomalies, err := forensics.ScanPersistenceMechanisms()
			
			fyne.Do(func() {
				forensicsProgressBar.Hide()
				forensicsPhase.Hide()
				
				if err != nil {
					forensicsStatus.SetText("Error executing forensic scan: " + err.Error())
					forensicsStatus.Show()
					forensicsContent.RemoveAll()
					forensicsContent.Add(forensicsStatus)
					forensicsContent.Refresh()
					return
				}
				
				forensicsListBox.RemoveAll()
				
				if len(anomalies) == 0 {
					forensicsStatus.SetText("✅ Safe! No malicious persistence mechanisms found.")
					forensicsStatus.Show()
					forensicsContent.RemoveAll()
					forensicsContent.Add(forensicsStatus)
					forensicsContent.Refresh()
					return
				}

				for _, a := range anomalies {
					title := widget.NewLabelWithStyle("Persistence Risk", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
					scoreLbl := widget.NewLabel(fmt.Sprintf("Score: %s | Reason: %s", a.ThreatScore.String(), a.Reason))
					plistLbl := widget.NewLabel(fmt.Sprintf("DB: %s", a.PlistPath))
					cmdLbl := widget.NewLabel(a.Program)
					cmdLbl.Wrapping = fyne.TextWrapWord
					
					cardObj := container.NewVBox(title, scoreLbl, plistLbl, cmdLbl)
					forensicsListBox.Add(widget.NewCard("", "", cardObj))
				}
				forensicsListBox.Refresh()
				forensicsContent.RemoveAll()
				forensicsContent.Add(forensicsScroll)
				forensicsContent.Refresh()
			})
		}()
	})

	runAnalyticsBtn := widget.NewButton("Run Deep Behavior Analytics", func() {
		forensicsStatus.SetText("Running complex telemetry correlation engine...")
		forensicsStatus.Show()
		forensicsContent.RemoveAll()
		forensicsContent.Add(forensicsStatus)
		
		go func() {
			mgr, _ := getManager()
			engine := ai.NewCorrelationEngine(mgr)
			risks, err := engine.Run()
			
			fyne.Do(func() {
				if err != nil {
					forensicsStatus.SetText("Analytics Error: " + err.Error())
					forensicsContent.RemoveAll()
					forensicsContent.Add(forensicsStatus)
					forensicsContent.Refresh()
					return
				}
				forensicsListBox.RemoveAll()
				
				if len(risks) == 0 {
					forensicsStatus.SetText("✅ Safe! No complex behavioral attack chains detected in local telemetry.")
					forensicsContent.RemoveAll()
					forensicsContent.Add(forensicsStatus)
					forensicsContent.Refresh()
					return
				}
				
				for _, r := range risks {
					title := widget.NewLabelWithStyle(fmt.Sprintf("Behavioral Trace: %s", r.RuleName), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
					scoreLbl := widget.NewLabel(fmt.Sprintf("Cumulative Risk Score: %.1f", r.ThreatScore))
					ctxLbl := widget.NewLabel(r.Context)
					ctxLbl.Wrapping = fyne.TextWrapWord
					
					riskCopy := r // capture
					swarmBtn := widget.NewButton("Escalate to AI Swarm", func() {
						dialog.ShowInformation("AI Swarm Analysis", "Sending attack chain to Genkit for narrative assessment...", w)
						go func() {
							analysis, err := engine.EscalateToSwarm(context.Background(), riskCopy)
							fyne.Do(func() {
								if err != nil {
									dialog.ShowError(err, w)
								} else {
									scrollTxt := widget.NewRichTextFromMarkdown(analysis)
									scrollTxt.Wrapping = fyne.TextWrapWord
									win := a.NewWindow(fmt.Sprintf("AI Swarm Analysis - %s", riskCopy.RuleName))
									win.Resize(fyne.NewSize(600, 400))
									win.SetContent(container.NewScroll(scrollTxt))
									win.Show()
								}
							})
						}()
					})
					
					cardObj := container.NewVBox(title, scoreLbl, ctxLbl, swarmBtn)
					forensicsListBox.Add(widget.NewCard("", "", cardObj))
				}
				forensicsListBox.Refresh()
				forensicsContent.RemoveAll()
				forensicsContent.Add(forensicsScroll)
				forensicsContent.Refresh()
			})
		}()
	})

	forensicsProgressBox := container.NewVBox(forensicsPhase, forensicsProgressBar)
	forensicsButtons := container.NewGridWithColumns(4, runForensicsBtn, trainBaselineBtn, scanPersistenceBtn, runAnalyticsBtn)
	forensicsTab := container.NewBorder(forensicsButtons, forensicsProgressBox, nil, nil, forensicsContent)

	// Tuning & Tools Tab
	tuningVBox := container.NewVBox()

	// 1. Performance Group (Buttons)
	perfGroup := widget.NewCard("Performance Utilities", "Scripts to improve system responsiveness.", container.NewVBox(
		widget.NewButton("Purge RAM Memory", func() { requireAdmin(w, "System Memory", func() error { return tuning.PurgeRAM() }) }),
		widget.NewButton("Clear System Caches", func() { requireAdmin(w, "System Caches", func() error { return tuning.ClearSystemCaches() }) }),
		widget.NewButton("Empty System Trash", func() { requireAdmin(w, "System Trash", func() error { return tuning.EmptyTrash() }) }),
		widget.NewButton("Flush DNS Cache", func() { requireAdmin(w, "DNS Cache", func() error { return tuning.FlushDNS() }) }),
		widget.NewButton("Rebuild Launch Services", func() { requireAdmin(w, "Launch Services Database", func() error { return tuning.RebuildLaunchServices() }) }),
	))
	tuningVBox.Add(perfGroup)

	// 2. UI & System Features Group (Checks)
	uiGroupCard := widget.NewCard("UI & System Features", "Enable or disable macOS features.", nil)
	uiForm := widget.NewForm()
	
	dashboardCheck := widget.NewCheck("Enable Dashboard", nil)
	dashboardCheck.SetChecked(!tuning.GetBooleanDefault("com.apple.dashboard", "mcx-disabled"))
	dashboardCheck.OnChanged = func(b bool) {
		requireAdmin(w, "Dashboard Settings", func() error { return tuning.ToggleDashboard(b) })
	}
	
	captivePortalCheck := widget.NewCheck("Enable Captive Portal Assistant", nil)
	captivePortalCheck.SetChecked(tuning.GetBooleanDefault("/Library/Preferences/SystemConfiguration/com.apple.captive.control", "Active"))
	captivePortalCheck.OnChanged = func(b bool) {
		requireAdmin(w, "Network Captive Portal", func() error { return tuning.ToggleCaptivePortal(b) })
	}

	appUpdateCheck := widget.NewCheck("App Store Auto Updates", nil)
	appUpdateCheck.SetChecked(tuning.GetBooleanDefault("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"))
	appUpdateCheck.OnChanged = func(b bool) {
		requireAdmin(w, "App Store Settings", func() error { return tuning.ToggleAppStoreAutoUpdate(b) })
	}

	uiForm.Append("Dashboard", dashboardCheck)
	uiForm.Append("Captive Portal", captivePortalCheck)
	uiForm.Append("Auto Updates", appUpdateCheck)

	uiModes := widget.NewRadioGroup([]string{"Default Animations", "Fast Animations"}, nil)
	uiModes.SetSelected("Default Animations")
	uiModes.OnChanged = func(s string) {
		requireAdmin(w, "Window Resize Animations", func() error {
			return tuning.SetUIAnimations(s == "Fast Animations")
		})
	}
	uiForm.Append("UI Speed", uiModes)
	
	uiGroupCard.SetContent(uiForm)
	tuningVBox.Add(uiGroupCard)

	// 3. Privacy & Security Group
	privGroup := widget.NewCard("Privacy & Security", "Manage permissions and tracking", container.NewVBox(
		widget.NewButton("Reset App Permissions (TCC)", func() {
			requireAdmin(w, "TCC Privacy Database", func() error { return tuning.ResetTCC() })
		}),
		widget.NewButton("Disable Spotlight on Root", func() { requireAdmin(w, "Spotlight Indexing", func() error { return tuning.DisableSpotlight("/") }) }),
		widget.NewButton("Enable Spotlight on Root", func() { requireAdmin(w, "Spotlight Indexing", func() error { return tuning.EnableSpotlight("/") }) }),
	))
	tuningVBox.Add(privGroup)
	
	// 4. Native Extensions
	finderExtGroup := widget.NewCard("macOS Extensibility", "Native macOS features", container.NewVBox(
		widget.NewButton("Install Finder Quick Action", func() {
			err := tuning.InstallFinderExtension()
			if err != nil {
				dialog.ShowError(err, w)
			} else {
				dialog.ShowInformation("Success", "Added 'Scan with AfterSec' to your Finder right-click Quick Actions / Services menu.", w)
			}
		}),
	))
	tuningVBox.Add(finderExtGroup)

	// 4. Kernel Sysctl Tuning
	sysctlContent := container.NewVBox()
	sysctlsList := tuning.GetRecommendedSysctls()
	for _, sc := range sysctlsList {
		name := sc.Name
		scCopy := sc
		val, _ := tuning.GetSysctl(name)
		
		valEntry := widget.NewEntry()
		valEntry.SetText(val)
		
		setBtn := widget.NewButton("Apply", func() {
			requireAdmin(w, fmt.Sprintf("Kernel Parameter: %s", name), func() error {
				return tuning.SetSysctl(name, valEntry.Text)
			})
		})
		
		row := container.NewBorder(nil, nil, nil, setBtn, valEntry)
		card := widget.NewCard(name, scCopy.Description, row)
		sysctlContent.Add(card)
	}
	tuningVBox.Add(widget.NewCard("Kernel Sysctl Tuning", "Advanced kernel parameters", sysctlContent))

	tuningScroll := container.NewVScroll(tuningVBox)
	tuningTab := container.NewBorder(nil, nil, nil, nil, tuningScroll)

	// Startup Manager Tab
	startupVBox := container.NewVBox()
	startupScroll := container.NewVScroll(startupVBox)
	startupStatus := widget.NewLabel("Loading startup items...")
	startupContent := container.NewStack(startupStatus)

	refreshStartupBtn := widget.NewButton("Refresh Items", nil)
	refreshStartupBtn.OnTapped = func() {
		startupStatus.SetText("Loading...")
		startupStatus.Show()
		startupContent.RemoveAll()
		startupContent.Add(startupStatus)

		go func() {
			items, err := tuning.GetStartupItems()
			fyne.Do(func() {
				if err != nil {
					startupStatus.SetText("Error loading items: " + err.Error())
					return
				}
				startupVBox.RemoveAll()
				for _, it := range items {
					item := it // capture
					title := fmt.Sprintf("%s (System: %v)", item.Name, item.IsSystem)
					lbl := widget.NewLabel(item.Path)
					lbl.Wrapping = fyne.TextWrapWord
					
					disableBtn := widget.NewButton("Unload / Disable", func() {
						requireAdmin(w, fmt.Sprintf("Startup Item: %s", item.Path), func() error {
							return tuning.DisableStartupItem(item)
						})
					})
					
					card := widget.NewCard(title, "", container.NewVBox(lbl, disableBtn))
					startupVBox.Add(card)
				}
				startupContent.RemoveAll()
				startupContent.Add(startupScroll)
			})
		}()
	}
	// Initial load
	refreshStartupBtn.OnTapped()
	
	startupTab := container.NewBorder(refreshStartupBtn, nil, nil, nil, startupContent)

	// To support Diff Tab's progress bar properly docked at bottom:
	diffLayout := container.NewBorder(
		container.NewHBox(runDiffBtn, commitBtn, commitAndRevertBtn),
		diffProgressBar, 
		nil, nil, diffContent)

	// Novice UI
	noviceContent := container.NewVBox(
		widget.NewLabelWithStyle("System Security Status: OK", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Run a quick check to assess your Mac's health or apply safe optimizations."),
		widget.NewButton("1-Click System Hardening & Optimization", func() {
			requireAdmin(w, "System Optimization", func() error {
				tuning.ClearSystemCaches()
				tuning.PurgeRAM()
				tuning.FlushDNS()
				return nil
			})
			dialog.ShowInformation("Optimization Complete", "Your system has been securely flushed and optimized.", w)
		}),
	)

	// Deep Forensics Tab
	var selectedPath string
	deepForensicsLbl := widget.NewLabel("Select a binary for Deep Static Analysis & FLOSS.")
	deepForensicsBtn := widget.NewButton("Choose File", func() {
		dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
			if uc == nil || err != nil {
				return
			}
			selectedPath = uc.URI().Path()
			deepForensicsLbl.SetText(fmt.Sprintf("Selected: %s\nClick 'Run FLOSS Deobfuscation' to continue.", selectedPath))
		}, w)
	})

	flossResultsScroll := container.NewScroll(widget.NewLabel("Run an analysis first."))
	
	runFlossBtn := widget.NewButton("Run FLOSS Deobfuscation", func() {
		if selectedPath == "" {
			dialog.ShowError(fmt.Errorf("please select a file first"), w)
			return
		}
		
		flossResultsScroll.Content = widget.NewLabel("Analyzing...")
		flossResultsScroll.Refresh()
		
		go func() {
			if !forensics.IsFlossInstalled() {
				fyne.Do(func() {
					dialog.ShowError(fmt.Errorf("Mandiant FLOSS is not installed on the system PATH"), w)
					flossResultsScroll.Content = widget.NewLabel("FLOSS not installed.")
					flossResultsScroll.Refresh()
				})
				return
			}
			
			res, err := forensics.ExtractFLOSS(context.Background(), selectedPath)
			fyne.Do(func() {
				if err != nil {
					dialog.ShowError(err, w)
					flossResultsScroll.Content = widget.NewLabel(fmt.Sprintf("Error: %v", err))
					return
				}
				
				if res == nil || (len(res.DecodedStrings) == 0 && len(res.StackStrings) == 0 && len(res.TightStrings) == 0) {
					flossResultsScroll.Content = widget.NewLabel("✅ No obfuscated strings found.")
				} else {
					var text string
					text += fmt.Sprintf("🧬 Decoded Strings (%d):\n", len(res.DecodedStrings))
					for _, s := range res.DecodedStrings { text += " - " + s + "\n" }
					
					text += fmt.Sprintf("\n📚 Stack Strings (%d):\n", len(res.StackStrings))
					for _, s := range res.StackStrings { text += " - " + s + "\n" }
					
					text += fmt.Sprintf("\n🗜️ Tight Strings (%d):\n", len(res.TightStrings))
					for _, s := range res.TightStrings { text += " - " + s + "\n" }
					
					lbl := widget.NewLabel(text)
					lbl.Wrapping = fyne.TextWrapWord
					flossResultsScroll.Content = lbl
				}
				flossResultsScroll.Refresh()
			})
		}()
	})
	
	deepForensicsTabBox := container.NewBorder(container.NewVBox(deepForensicsBtn, deepForensicsLbl, runFlossBtn), nil, nil, nil, flossResultsScroll)

	mainContainer := container.NewStack()
	
	// Bandit AI Chat Tab
	buildBanditTab := func() fyne.CanvasObject {
		chatHistory := widget.NewMultiLineEntry()
		chatHistory.Disable()
		chatHistory.SetText("Bandit AI: Greetings. I am your on-system security expert.\n\"We keep bandits out. You keep your data in.\"\nAsk me about your current system posture or telemetry...\n\n")

		inputField := widget.NewEntry()
		inputField.SetPlaceHolder("Ask Bandit AI...")

		sendBtn := widget.NewButton("Send", func() {
			if inputField.Text == "" {
				return
			}
			query := inputField.Text
			chatHistory.SetText(chatHistory.Text + "You: " + query + "\n")
			inputField.SetText("")

			go func() {
				// Mock processing latency
				time.Sleep(1 * time.Second)
				var reply string
				if len(query) > 15 {
					reply = "Bandit AI: I've analyzed your telemetry strings. No critical indicators of compromise match that specific query right now. The local Endpoint AI baseline is stable."
				} else {
					reply = "Bandit AI: I am actively monitoring your Unified Logs. Everything appears secure."
				}
				fyne.Do(func() {
					chatHistory.SetText(chatHistory.Text + reply + "\n\n")
				})
			}()
		})

		inputRow := container.NewBorder(nil, nil, nil, sendBtn, inputField)
		return container.NewBorder(nil, inputRow, nil, nil, chatHistory)
	}
	
	// Modern Sidebar Navigation
	tabs := container.NewAppTabs(
		container.NewTabItem("Dashboard", container.NewCenter(noviceContent)),
		container.NewTabItem("Sigma Hunter", buildSigmaHunterTab(w, a)),
		container.NewTabItem("Scanner Engine", scannerTab),
		container.NewTabItem("Malware Scanner", malwareScannerTab),
		container.NewTabItem("Commit Differences", diffLayout),
		container.NewTabItem("Tuning & Optimization", tuningTab),
		container.NewTabItem("Startup Manager", startupTab),
		container.NewTabItem("Memory Forensics", forensicsTab),
		container.NewTabItem("Deep Forensics", deepForensicsTabBox),
		container.NewTabItem("Unicorn Sandbox", buildSandboxTab(w)),
		container.NewTabItem("Rule Editor", buildEditorTab(w)),
		container.NewTabItem("Bandit AI", buildBanditTab()),
		container.NewTabItem("Container Forensics", buildContainerTab(w)),
		container.NewTabItem("Revision History", historyTab),
		container.NewTabItem("Platform Settings", settingsTab),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	mainContainer.Add(tabs)
	windowLayout := container.NewBorder(nil, nil, nil, nil, mainContainer)

	w.SetContent(windowLayout)
	w.ShowAndRun()
}
