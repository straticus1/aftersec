package ai

import (
	"strings"
	"testing"
)

func TestLibraryPromptKeepsHardSignals(t *testing.T) {
	text := LibrarySwarmPrompt(LibraryTriage{
		Score:  5,
		Format: "mach-o",
		Hard:   []string{"libHelper.dylib is unsigned inside a signed host"},
	})
	if !strings.Contains(text, "Do not clear a hard signal") || !strings.Contains(text, "unsigned inside a signed host") {
		t.Fatal(text)
	}
}
