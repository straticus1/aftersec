package main

import (
	"strings"
	"testing"
)

func TestDetonationRejectsInvalidVerdicts(t *testing.T) {
	for _, input := range []string{"{}", "null", `{"verdict":"deny"}`, `{"verdict":"UNKNOWN"}`, `{"verdict":"ALLOW"} {}`, `{"verdict":"ALLOW"`, strings.Repeat(" ", 65537)} {
		if _, err := decodeDetonationVerdict(strings.NewReader(input)); err == nil {
			t.Errorf("accepted %q", input[:min(len(input), 60)])
		}
	}
	for _, verdict := range []string{"ALLOW", "DENY"} {
		result, err := decodeDetonationVerdict(strings.NewReader(`{"verdict":"` + verdict + `","score":10}`))
		if err != nil || result.Verdict != verdict {
			t.Fatalf("%+v %v", result, err)
		}
	}
}
