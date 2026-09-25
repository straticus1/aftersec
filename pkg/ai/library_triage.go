package ai

import (
	"context"
	"fmt"
	"strings"
)

// LibraryTriage is the only record the swarm is allowed to see.
type LibraryTriage struct {
	Score  int
	Hard   []string
	Weak   []string
	Format string
}

// LibrarySwarmPrompt builds the triage request. Hard signals are repeated so a
// narrative cannot be stored as if they were withdrawn.
func LibrarySwarmPrompt(t LibraryTriage) string {
	return fmt.Sprintf(`You are triaging an endpoint library dossier. Do not clear a hard signal. If you disagree, say which hard signal a human should verify. Do not claim the file is benign.
Score: %d
Format: %s
Hard signals:
%s
Weak signals:
%s`, t.Score, t.Format, listOrNone(t.Hard), listOrNone(t.Weak))
}

// TriageLibraryDossier sends a promoted dossier to the existing swarm.
// The returned text always keeps the hard signals, including when the model errors.
func TriageLibraryDossier(ctx context.Context, t LibraryTriage) (string, error) {
	prompt := LibrarySwarmPrompt(t)
	narrative, err := AnalyzeThreatSwarm(ctx, prompt)
	kept := "hard signals remain: " + listOrNone(t.Hard)
	if err != nil {
		return kept, err
	}
	return narrative + "\n" + kept, nil
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, "\n")
}
