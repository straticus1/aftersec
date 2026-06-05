//go:build darwin

package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"aftersec/pkg/tuning"
)

func buildTuningTab(w fyne.Window) fyne.CanvasObject {
	tuningVBox := container.NewVBox()

	perfGroup := widget.NewCard("Performance Utilities", "Scripts to improve system responsiveness.", container.NewVBox(
		widget.NewButton("Purge RAM Memory", func() { requireAdmin(w, "System Memory", func() error { return tuning.PurgeRAM() }) }),
		widget.NewButton("Clear System Caches", func() { requireAdmin(w, "System Caches", func() error { return tuning.ClearSystemCaches() }) }),
		widget.NewButton("Empty System Trash", func() { requireAdmin(w, "System Trash", func() error { return tuning.EmptyTrash() }) }),
		widget.NewButton("Flush DNS Cache", func() { requireAdmin(w, "DNS Cache", func() error { return tuning.FlushDNS() }) }),
		widget.NewButton("Rebuild Launch Services", func() { requireAdmin(w, "Launch Services Database", func() error { return tuning.RebuildLaunchServices() }) }),
	))
	tuningVBox.Add(perfGroup)

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

	privGroup := widget.NewCard("Privacy & Security", "Manage permissions and tracking", container.NewVBox(
		widget.NewButton("Reset App Permissions (TCC)", func() {
			requireAdmin(w, "TCC Privacy Database", func() error { return tuning.ResetTCC() })
		}),
		widget.NewButton("Disable Spotlight on Root", func() {
			requireAdmin(w, "Spotlight Indexing", func() error { return tuning.DisableSpotlight("/") })
		}),
		widget.NewButton("Enable Spotlight on Root", func() {
			requireAdmin(w, "Spotlight Indexing", func() error { return tuning.EnableSpotlight("/") })
		}),
	))
	tuningVBox.Add(privGroup)

	finderExtGroup := widget.NewCard("macOS Extensibility", "Native macOS features", container.NewVBox(
		widget.NewButton("Install Finder Quick Action", func() {
			if err := tuning.InstallFinderExtension(); err != nil {
				dialog.ShowError(err, w)
			} else {
				dialog.ShowInformation("Success", "Added 'Scan with AfterSec' to your Finder right-click Quick Actions / Services menu.", w)
			}
		}),
	))
	tuningVBox.Add(finderExtGroup)

	sysctlContent := container.NewVBox()
	for _, sc := range tuning.GetRecommendedSysctls() {
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
		sysctlContent.Add(widget.NewCard(name, scCopy.Description, row))
	}
	tuningVBox.Add(widget.NewCard("Kernel Sysctl Tuning", "Advanced kernel parameters", sysctlContent))

	return container.NewBorder(nil, nil, nil, nil, container.NewVScroll(tuningVBox))
}
