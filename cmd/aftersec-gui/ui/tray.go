package ui

import (
	"os/exec"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

// SetupTray configures the macOS / System menu bar icon and quick actions
func SetupTray(a fyne.App, w fyne.Window) {
	// Enable Background MenuBar Lifecycle By Hiding (Not Quitting) Window on Red X
	w.SetCloseIntercept(func() {
		w.Hide()
	})

	if desk, ok := a.(desktop.App); ok {
		daemonStatus := "Daemon Status: Unknown State"
		if out, err := exec.Command("pgrep", "-f", "aftersecd").Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			daemonStatus = "Daemon Status: Secure (Active)"
		}

		m := fyne.NewMenu("AfterSec Control Panel",
			fyne.NewMenuItem(daemonStatus, func() {}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Show Security Center", func() {
				w.Show()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Restart Sensors (Requires Admin)", func() {
				// Fire a system hangup to reset the daemon rules in the background
				exec.Command("sudo", "killall", "-HUP", "aftersecd").Run()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit Core Platform", func() {
				a.Quit()
			}),
		)
		desk.SetSystemTrayMenu(m)
	}
}
