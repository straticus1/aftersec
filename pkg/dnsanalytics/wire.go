package dnsanalytics

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

// DecodeWireQuery accepts a DNS message transported by UDP, TCP (two-byte
// length prefix), or RFC 8484 DoH GET/POST payload.
func DecodeWireQuery(protocol string, payload []byte, requestURL *url.URL) (string, error) {
	switch protocol {
	case "tcp":
		if len(payload) < 2 {
			return "", fmt.Errorf("truncated TCP DNS frame")
		}
		length := int(payload[0])<<8 | int(payload[1])
		if length == 0 || length != len(payload)-2 {
			return "", fmt.Errorf("invalid TCP DNS frame length")
		}
		payload = payload[2:]
	case "https-get":
		if requestURL == nil {
			return "", fmt.Errorf("DoH request URL is required")
		}
		var err error
		payload, err = base64.RawURLEncoding.DecodeString(requestURL.Query().Get("dns"))
		if err != nil {
			return "", fmt.Errorf("decode DoH query: %w", err)
		}
	case "udp", "https-post":
	default:
		return "", fmt.Errorf("unsupported DNS transport")
	}
	return decodeQuestionName(payload)
}

func decodeQuestionName(packet []byte) (string, error) {
	if len(packet) < 13 || packet[2]&0x80 != 0 || packet[4] == 0 && packet[5] == 0 {
		return "", fmt.Errorf("invalid DNS question")
	}
	offset := 12
	domain := ""
	for labels := 0; labels < 127; labels++ {
		if offset >= len(packet) {
			return "", fmt.Errorf("truncated DNS question")
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			return NormalizeDomain(domain)
		}
		if length > 63 || offset+length > len(packet) || length&0xc0 != 0 {
			return "", fmt.Errorf("invalid DNS label encoding")
		}
		if domain != "" {
			domain += "."
		}
		domain += string(packet[offset : offset+length])
		offset += length
	}
	return "", fmt.Errorf("too many DNS labels")
}
