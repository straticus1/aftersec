package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
)

const maxAttestationFieldBytes = 1 << 20

// SignedQuoteVerifier verifies a normalized quote signed by a platform-specific
// attestation trust gateway. Threats: signatures bind platform, hardware ID,
// one-time nonce, and endpoint public key without concatenation ambiguity.
// Native Apple/TPM evidence validation remains the gateway/adapter's duty.
type SignedQuoteVerifier struct {
	platformKeys map[string]ed25519.PublicKey
}

func NewSignedQuoteVerifier(keys map[string]ed25519.PublicKey) *SignedQuoteVerifier {
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for platform, key := range keys {
		copied[platform] = append(ed25519.PublicKey(nil), key...)
	}
	return &SignedQuoteVerifier{platformKeys: copied}
}

func LoadSignedQuoteVerifier(platformKeyFiles map[string]string) (*SignedQuoteVerifier, error) {
	if len(platformKeyFiles) == 0 {
		return nil, fmt.Errorf("at least one attestation trust key is required")
	}
	keys := make(map[string]ed25519.PublicKey, len(platformKeyFiles))
	for platform, path := range platformKeyFiles {
		if platform == "" || path == "" {
			return nil, fmt.Errorf("attestation platform and trust-key path are required")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s attestation trust key: %w", platform, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode %s attestation trust key", platform)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s attestation trust key: %w", platform, err)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s attestation trust key is not Ed25519", platform)
		}
		keys[platform] = key
	}
	return NewSignedQuoteVerifier(keys), nil
}

func QuoteMessage(evidence Evidence) []byte {
	message := []byte("aftersec-attestation-quote-v1\x00")
	for _, field := range [][]byte{
		[]byte(evidence.Platform),
		[]byte(evidence.HardwareID),
		evidence.Nonce,
		evidence.PublicKey,
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		message = append(message, length[:]...)
		message = append(message, field...)
	}
	return message
}

func (v *SignedQuoteVerifier) Verify(_ context.Context, evidence Evidence) error {
	key, ok := v.platformKeys[evidence.Platform]
	if !ok {
		return fmt.Errorf("untrusted attestation platform")
	}
	if evidence.HardwareID == "" || len(evidence.Nonce) != 32 || len(evidence.PublicKey) == 0 ||
		len(evidence.HardwareID) > maxAttestationFieldBytes || len(evidence.Platform) > maxAttestationFieldBytes ||
		len(evidence.PublicKey) > maxAttestationFieldBytes || len(evidence.Quote) != ed25519.SignatureSize {
		return fmt.Errorf("malformed attestation evidence")
	}
	if !ed25519.Verify(key, QuoteMessage(evidence), evidence.Quote) {
		return fmt.Errorf("attestation quote signature invalid")
	}
	return nil
}
