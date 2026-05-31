package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// AfterSecTheme forces a dark, hacker-style theme for the security tool
type AfterSecTheme struct{}

func (m AfterSecTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	if n == theme.ColorNameBackground {
		return color.NRGBA{R: 20, G: 20, B: 20, A: 255} // Dark background
	}
	if n == theme.ColorNamePrimary {
		return color.NRGBA{R: 0, G: 200, B: 100, A: 255} // Hacker Green primary accents
	}
	return theme.DefaultTheme().Color(n, theme.VariantDark)
}

func (m AfterSecTheme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(s)
}

func (m AfterSecTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(n)
}

func (m AfterSecTheme) Size(n fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(n)
}
