package selfprotect

import (
	"errors"
	"sort"
)

var (
	ErrUnauthorizedStop     = errors.New("unauthorized agent stop")
	ErrEntitlementRevoked   = errors.New("required agent entitlement revoked")
	ErrInvalidStopPolicy    = errors.New("invalid stop authorization policy")
)

func (g *Guard) AuthorizeStop(signerTrusted bool) error {
	if g == nil {
		return ErrInvalidStopPolicy
	}
	if !signerTrusted {
		return ErrUnauthorizedStop
	}
	return nil
}

func EntitlementsRevoked(required, observed []string) error {
	if len(required) == 0 {
		return ErrInvalidStopPolicy
	}
	have := make(map[string]struct{}, len(observed))
	for _, item := range observed {
		if item != "" {
			have[item] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for _, need := range required {
		if need == "" {
			return ErrInvalidStopPolicy
		}
		if _, ok := have[need]; !ok {
			missing = append(missing, need)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return ErrEntitlementRevoked
}
