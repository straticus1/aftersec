//go:build linux

package attestation

import (
	"context"
	"fmt"
	"os"
)

// TPMAttester opens the kernel TPM device and refuses to invent a quote.
// A present device without a provisioned attestation key is still an error.
//
// Threats: software signatures and stand-in quotes are not TPM evidence.
// Quote verification against PCR policy remains the server verifier's duty.
type TPMAttester struct{}

func NewPlatformAttester() (HardwareAttester, error) { return TPMAttester{}, nil }

func (TPMAttester) Platform() string { return "tpm" }

func (TPMAttester) EnsureIdentity(ctx context.Context) (string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	device, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		return "", nil, fmt.Errorf("open TPM device: %w", err)
	}
	if err := device.Close(); err != nil {
		return "", nil, fmt.Errorf("close TPM device: %w", err)
	}
	return "", nil, fmt.Errorf("TPM device is present but no attestation key is provisioned")
}

func (TPMAttester) Quote(context.Context, []byte) ([]byte, error) {
	return nil, fmt.Errorf("TPM quote requires a provisioned attestation key")
}
