package attestation

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
)

const maxHardwareQuoteBytes = 1 << 20

// ErrHardwareAttestation means no hardware quote is available. Callers must
// not replace it with a software signature.
var ErrHardwareAttestation = errors.New("hardware attestation unavailable")

// HardwareAttester collects a platform quote. EnsureIdentity may create a
// hardware-bound key. Quote must be the platform attestation blob for nonce.
//
// Threats: a missing device, a refused API, or a software-sized signature is
// not evidence. This package does not sign a substitute quote.
type HardwareAttester interface {
	Platform() string
	EnsureIdentity(context.Context) (hardwareID string, publicKey []byte, err error)
	Quote(context.Context, []byte) ([]byte, error)
}

// Collect returns evidence only when the attester produced a hardware quote
// bound to nonce. A 64-byte quote is rejected because that is the size of a
// raw Ed25519 signature, which is the software enrollment path.
func Collect(ctx context.Context, attester HardwareAttester, nonce []byte) (Evidence, error) {
	if attester == nil || len(nonce) != 32 {
		return Evidence{}, ErrHardwareAttestation
	}
	hardwareID, publicKey, err := attester.EnsureIdentity(ctx)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %v", ErrHardwareAttestation, err)
	}
	quote, err := attester.Quote(ctx, nonce)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %v", ErrHardwareAttestation, err)
	}
	if hardwareID == "" || attester.Platform() == "" || len(publicKey) == 0 || len(quote) == 0 ||
		len(hardwareID) > 256 || len(publicKey) > maxHardwareQuoteBytes || len(quote) > maxHardwareQuoteBytes ||
		len(quote) == 64 {
		return Evidence{}, ErrHardwareAttestation
	}
	evidence := Evidence{
		HardwareID: hardwareID,
		Platform:   attester.Platform(),
		Nonce:      append([]byte(nil), nonce...),
		Quote:      append([]byte(nil), quote...),
		PublicKey:  append([]byte(nil), publicKey...),
	}
	if subtle.ConstantTimeCompare(evidence.Nonce, nonce) != 1 {
		return Evidence{}, ErrHardwareAttestation
	}
	return evidence, nil
}
