//go:build linux

package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"aftersec/pkg/tuning"
)

func buildTuningTab(w fyne.Window) fyne.CanvasObject {
	tuningVBox := container.NewVBox()

	perfGroup := widget.NewCard("Performance Utilities", "Scripts to improve system responsiveness.", container.NewVBox(
		widget.NewButton("Drop Page Cache", func() { requireAdmin(w, "Kernel Page Cache", func() error { return tuning.PurgeRAM() }) }),
		widget.NewButton("Clear System Caches", func() { requireAdmin(w, "System Caches", func() error { return tuning.ClearSystemCaches() }) }),
		widget.NewButton("Empty Trash", func() { requireAdmin(w, "User Trash", func() error { return tuning.EmptyTrash() }) }),
		widget.NewButton("Flush DNS Cache", func() { requireAdmin(w, "DNS Resolver Cache", func() error { return tuning.FlushDNS() }) }),
	))
	tuningVBox.Add(perfGroup)

	privGroup := widget.NewCard("Privacy & Security", "Manage system permissions.", container.NewVBox(
		widget.NewButton("Disable Locate Database Indexing", func() {
			requireAdmin(w, "locate/mlocate database", func() error { return tuning.DisableSpotlight("/") })
		}),
		widget.NewButton("Enable Locate Database Indexing", func() {
			requireAdmin(w, "locate/mlocate database", func() error { return tuning.EnableSpotlight("/") })
		}),
	))
	tuningVBox.Add(privGroup)

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
	tuningVBox.Add(widget.NewCard("Kernel Sysctl Hardening", "Linux kernel security parameters.", sysctlContent))

	return container.NewBorder(nil, nil, nil, nil, container.NewVScroll(tuningVBox))
}
