//go:build linux

package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func buildContainerTab(_ fyne.Window) fyne.CanvasObject {
	title := widget.NewLabelWithStyle("Container Forensics", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	msg := widget.NewLabel("Container forensics (macOS .app bundle signing and .pkg installer analysis)\nare not available on Linux.")
	msg.Alignment = fyne.TextAlignCenter
	msg.Wrapping = fyne.TextWrapWord
	return container.NewCenter(container.NewVBox(title, msg))
}
