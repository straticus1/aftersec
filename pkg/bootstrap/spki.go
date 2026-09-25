package bootstrap

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
)

func pemPublic(public ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap public key: %w", err)
	}
	return der, nil
}
