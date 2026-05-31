package main

import (
	"fmt"
	"strings"

	"aftersec/pkg/editor"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// highlightCode provides rudimentary syntax highlighting for the Live Preview using RichText.
func highlightCode(content string) []widget.RichTextSegment {
	var segments []widget.RichTextSegment
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			segments = append(segments, &widget.TextSegment{Text: "\n"})
			continue
		}

		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			segments = append(segments, &widget.TextSegment{
				Text:  line + "\n",
				Style: widget.RichTextStyle{ColorName: theme.ColorNameDisabled, Inline: true},
			})
			continue
		}

		// Very rudimentary tokenization
		words := strings.SplitAfter(line, " ")
		for _, w := range words {
			trimmed := strings.TrimSpace(w)
			switch trimmed {
			case "def", "if", "else", "elif", "return", "for", "in", "and", "or", "not", "ACTION_ALLOW", "ACTION_BLOCK":
				segments = append(segments, &widget.TextSegment{
					Text:  w,
					Style: widget.RichTextStyle{ColorName: theme.ColorNamePrimary, Inline: true},
				})
			default:
				if strings.Contains(w, "\"") || strings.Contains(w, "'") {
					segments = append(segments, &widget.TextSegment{
						Text:  w,
						Style: widget.RichTextStyle{ColorName: theme.ColorNameSuccess, Inline: true},
					})
				} else {
					segments = append(segments, &widget.TextSegment{
						Text:  w,
						Style: widget.RichTextStyle{Inline: true},
					})
				}
			}
		}
		if i < len(lines)-1 {
			segments = append(segments, &widget.TextSegment{Text: "\n"})
		}
	}
	return segments
}

// buildEditorTab constructs a fully embedded IDE surface featuring an active 
// file tree, monospace entry, and localized state rollback handlers.
func buildEditorTab(w fyne.Window) fyne.CanvasObject {
	mgr, err := editor.NewManager()
	if err != nil {
		return widget.NewLabel("Error initializing editor manager: " + err.Error())
	}

	currentType := "scripts" // default tracking directory
	var activeFile string

	codeEntry := widget.NewMultiLineEntry()
	codeEntry.TextStyle.Monospace = true // Force IDE syntax formatting
	codeEntry.SetPlaceHolder("Select a file or create a new one to begin editing...")
	
	livePreview := widget.NewRichText()
	livePreviewScroll := container.NewScroll(livePreview)
	
	codeEntry.OnChanged = func(s string) {
		livePreview.Segments = highlightCode(s)
		livePreview.Refresh()
	}

	editorSplit := container.NewHSplit(codeEntry, livePreviewScroll)
	editorSplit.Offset = 0.5
	
	var filenames []string

	fileList := widget.NewList(
		func() int { return len(filenames) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(filenames[i])
		},
	)

	refreshList := func() {
		files, err := mgr.ListFiles(currentType)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		filenames = files
		fileList.Refresh()
	}

	fileList.OnSelected = func(id widget.ListItemID) {
		activeFile = filenames[id]
		content, err := mgr.ReadFile(currentType, activeFile)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		codeEntry.SetText(content)
	}

	typeSelector := widget.NewSelect([]string{"Starlark Scripts (.star)", "Distribution Scripts (Read-only)", "YARA Rules (.yar)"}, func(s string) {
		if strings.Contains(s, ".yar") {
			currentType = "rules"
		} else if strings.Contains(s, "Distribution") {
			currentType = "dist-scripts"
		} else {
			currentType = "scripts"
		}
		codeEntry.SetText("")
		activeFile = ""
		fileList.UnselectAll()
		refreshList()
	})
	typeSelector.SetSelected("Starlark Scripts (.star)") // Bootload

	saveBtn := widget.NewButton("Save", func() {
		if activeFile == "" {
			dialog.ShowInformation("No File Selected", "Please select or create a file to save.", w)
			return
		}
		if currentType == "dist-scripts" {
			entry := widget.NewEntry()
			entry.SetText(activeFile)
			dialog.ShowCustomConfirm("Save As Custom Script", "Save", "Cancel", container.NewVBox(
				widget.NewLabel("Distribution scripts are read-only.\nSave as a new custom script:"),
				entry,
			), func(b bool) {
				if b && entry.Text != "" {
					err := mgr.WriteFile("scripts", entry.Text, codeEntry.Text)
					if err != nil {
						dialog.ShowError(err, w)
						return
					}
					dialog.ShowInformation("Saved", fmt.Sprintf("Successfully saved as %s", entry.Text), w)
					typeSelector.SetSelected("Starlark Scripts (.star)")
				}
			}, w)
			return
		}
		if err := mgr.WriteFile(currentType, activeFile, codeEntry.Text); err != nil {
			dialog.ShowError(err, w)
			return
		}
		dialog.ShowInformation("Saved", fmt.Sprintf("Successfully saved %s", activeFile), w)
	})

	rollbackBtn := widget.NewButton("Rollback edits", func() {
		if activeFile == "" {
			return
		}
		dialog.ShowConfirm("Discard Changes", "Are you sure you want to revert to the last saved version on disk?", func(b bool) {
			if b {
				content, err := mgr.ReadFile(currentType, activeFile)
				if err != nil {
					dialog.ShowError(err, w)
				} else {
					codeEntry.SetText(content)
				}
			}
		}, w)
	})

	newBtn := widget.NewButton("New File", func() {
		ext := ".star"
		if currentType == "rules" {
			ext = ".yar"
		}
		entry := widget.NewEntry()
		dialog.ShowCustomConfirm("New File", "Create", "Cancel", container.NewVBox(
			widget.NewLabel("Enter filename (without extension):"),
			entry,
		), func(b bool) {
			if b && entry.Text != "" {
				newName := entry.Text + ext
				err := mgr.WriteFile(currentType, newName, "")
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				refreshList()
				// Auto select the new file
				for i, name := range filenames {
					if name == newName {
						fileList.Select(i)
						break
					}
				}
			}
		}, w)
	})

	helpBtn := widget.NewButton("Help", func() {
		helpMD := "# AfterSec GUI Script Editor\n\n" +
			"Welcome to the Script Editor! This embedded IDE lets you create and test automation scripts.\n\n" +
			"### How it works\n" +
			"- **Starlark Scripts:** These are evaluated upon system events. Return `ACTION_ALLOW` or `ACTION_BLOCK`.\n" +
			"- **Distribution Scripts:** These are standard policies shipped with AfterSec. They are read-only but can be modified and saved.\n" +
			"- **YARA Rules:** Used by the memory scanning engines to hunt for malware."
		helpRich := widget.NewRichTextFromMarkdown(helpMD)
		helpRich.Wrapping = fyne.TextWrapWord
		dialog.ShowCustom("Editor Help", "Close", container.NewScroll(helpRich), w)
	})

	refBtn := widget.NewButton("Language Reference", func() {
		refMD := "# Starlark Language Reference\n\n" +
			"Your security scripts run in an embedded Starlark environment.\n\n" +
			"### Core Variables & Constraints\n" +
			"- `ACTION_ALLOW` = Action permitted\n" +
			"- `ACTION_BLOCK` = Network, execution, or file action should be blocked\n\n" +
			"### Context `ctx` Fields\n" +
			"- **ctx.network**: `port`, `ip`, `protocol`\n" +
			"- **ctx.process**: `name`, `pid`, `uid`, `parent.name`\n" +
			"- **ctx.file**: `path`, `mode`\n\n" +
			"### Useful Functions\n" +
			"- `emit_alert(message, severity=\"\")`: Triggers an alert in the dashboard and logs.\n" +
			"- `fs.find(path, mode=\"\", user=\"\")`: Queries the local filesystem."
		refRich := widget.NewRichTextFromMarkdown(refMD)
		refRich.Wrapping = fyne.TextWrapWord
		scroll := container.NewScroll(refRich)
		scroll.SetMinSize(fyne.NewSize(500, 400))
		dialog.ShowCustom("Starlark Reference", "Close", scroll, w)
	})

	toolbar := container.NewHBox(typeSelector, newBtn, saveBtn, rollbackBtn, widget.NewLabel(" | "), helpBtn, refBtn)
	
	sidebar := container.NewBorder(widget.NewLabelWithStyle("Files", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), nil, nil, nil, fileList)
	split := container.NewHSplit(sidebar, editorSplit)
	split.Offset = 0.2 // Give file listing 20% of the screen by default

	return container.NewBorder(toolbar, nil, nil, nil, split)
}
