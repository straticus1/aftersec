//go:build darwin

package attestation

/*
#cgo LDFLAGS: -framework Foundation -framework Security
#include <stdint.h>
#include <stdlib.h>
int se_public_point(uint8_t **out, int *out_len);
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"fmt"
	"unsafe"
)

// SecureEnclaveAttester creates a non-exportable Secure Enclave key and
// refuses to invent an attestation quote. This SDK does not provide
// SecKeyCreateAttestation, and an App Attest object would belong to a
// different key.
//
// Threats: an exportable private key or a software signature is rejected.
// A successful identity without a quote is still not enrollment evidence.
type SecureEnclaveAttester struct {
	public []byte
	id     string
}

func NewPlatformAttester() (HardwareAttester, error) { return &SecureEnclaveAttester{}, nil }

func (a *SecureEnclaveAttester) Platform() string { return "secure-enclave" }

func (a *SecureEnclaveAttester) EnsureIdentity(ctx context.Context) (string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if a.id != "" {
		return a.id, append([]byte(nil), a.public...), nil
	}
	var raw *C.uint8_t
	var rawLen C.int
	rc := C.se_public_point(&raw, &rawLen)
	if raw != nil {
		defer C.free(unsafe.Pointer(raw))
	}
	if rc != 0 || raw == nil || rawLen <= 0 {
		return "", nil, fmt.Errorf("secure enclave key was not created (%d)", int(rc))
	}
	point := C.GoBytes(unsafe.Pointer(raw), rawLen)
	public, err := marshalP256PKIX(point)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(public)
	a.public = public
	a.id = fmt.Sprintf("se-%x", sum[:16])
	return a.id, append([]byte(nil), public...), nil
}

func (a *SecureEnclaveAttester) Quote(ctx context.Context, nonce []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.id == "" || len(nonce) != 32 {
		return nil, fmt.Errorf("secure enclave identity and 32-byte nonce are required")
	}
	return nil, fmt.Errorf("secure enclave key attestation API is not available; refusing a software quote")
}
