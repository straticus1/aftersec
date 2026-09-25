package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestMarshalP256PKIXRejectsTamperedPoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	encoded, err := marshalP256PKIX(point)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PublicKey); !ok {
		t.Fatalf("%T", parsed)
	}
	if _, err := marshalP256PKIX([]byte{0x04, 0x01}); err == nil {
		t.Fatal("short point accepted")
	}
	point[0] = 0x02
	if _, err := marshalP256PKIX(point); err == nil {
		t.Fatal("compressed point accepted")
	}
}
