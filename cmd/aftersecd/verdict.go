package main

import (
	"encoding/json"
	"fmt"
	"io"
)

type detonationVerdict struct {
	Verdict string `json:"verdict"`
	Score   int    `json:"score"`
}

func decodeDetonationVerdict(reader io.Reader) (detonationVerdict, error) {
	const limit = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return detonationVerdict{}, err
	}
	if len(data) > limit {
		return detonationVerdict{}, fmt.Errorf("detonation response exceeds limit")
	}
	var result detonationVerdict
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	if result.Verdict != "ALLOW" && result.Verdict != "DENY" {
		return result, fmt.Errorf("unknown detonation verdict")
	}
	return result, nil
}
