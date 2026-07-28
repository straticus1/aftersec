package dnsanalytics

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func wireQuestion(name string) []byte {
	packet := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"www", name, "com"} {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	return append(packet, 0, 0, 1, 0, 1)
}

func TestDecodeWireQueryTransports(t *testing.T) {
	packet := wireQuestion("example")
	tcp := append([]byte{byte(len(packet) >> 8), byte(len(packet))}, packet...)
	dohURL, err := url.Parse("https://resolver.example/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(packet))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		protocol string
		payload  []byte
		request  *url.URL
	}{
		{"udp", "udp", packet, nil},
		{"tcp", "tcp", tcp, nil},
		{"doh post", "https-post", packet, nil},
		{"doh get", "https-get", nil, dohURL},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeWireQuery(test.protocol, test.payload, test.request)
			if err != nil {
				t.Fatal(err)
			}
			if got != "www.example.com" {
				t.Fatalf("domain = %q", got)
			}
		})
	}
}

func TestDecodeWireQueryRejectsMalformedFrames(t *testing.T) {
	packet := wireQuestion("example")
	badTCP := append([]byte{0, byte(len(packet) + 1)}, packet...)
	if _, err := DecodeWireQuery("tcp", badTCP, nil); err == nil {
		t.Fatal("accepted invalid TCP frame length")
	}
	if _, err := DecodeWireQuery("https-get", nil, nil); err == nil {
		t.Fatal("accepted DoH GET without URL")
	}
}
