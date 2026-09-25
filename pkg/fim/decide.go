package fim

import "errors"

// DecideWrite reports whether an authorization event may proceed.
//
// Threats: a missing writer, an evidence failure, or a canary touch must not
// be allowed. A path outside the integrity roots is not a protected write.
// This does not decide self-protection or execution policy.
func DecideWrite(fimErr, evidenceErr error, canary bool) bool {
	if canary {
		return false
	}
	if fimErr == nil {
		return evidenceErr == nil
	}
	if errors.Is(fimErr, ErrOutsideCriticalPath) {
		return true
	}
	return false
}
