package core

import "fmt"

type Diff struct {
	Changes []string
}

func (d *Diff) HasChanges() bool {
	return len(d.Changes) > 0
}

func CompareStates(old, current *SecurityState) *Diff {
	diff := &Diff{}

	if old == nil || current == nil {
		diff.Changes = append(diff.Changes, "Comparing against nil state")
		return diff
	}

	oldMap := make(map[string]Finding)
	for _, f := range old.Findings {
		key := fmt.Sprintf("%s|%s", f.Category, f.Name)
		oldMap[key] = f
	}

	for _, curr := range current.Findings {
		key := fmt.Sprintf("%s|%s", curr.Category, curr.Name)
		if prev, exists := oldMap[key]; exists {
			if prev.CurrentVal != curr.CurrentVal || prev.Passed != curr.Passed {
				change := fmt.Sprintf("[%s] %s changed: '%s' (passed: %t) -> '%s' (passed: %t)",
					curr.Severity, curr.Name, prev.CurrentVal, prev.Passed, curr.CurrentVal, curr.Passed)
				diff.Changes = append(diff.Changes, change)
			}
			delete(oldMap, key)
		} else {
			diff.Changes = append(diff.Changes, fmt.Sprintf("New finding added: [%s] %s (value: %s)", curr.Severity, curr.Name, curr.CurrentVal))
		}
	}

	for _, prev := range oldMap {
		diff.Changes = append(diff.Changes, fmt.Sprintf("Finding removed: [%s] %s", prev.Severity, prev.Name))
	}

	return diff
}
