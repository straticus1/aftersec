package preserve

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

type bundleEnvelope struct {
	IncidentID string `json:"incident_id"`
	Reason     string `json:"reason"`
	SHA256     string `json:"sha256"`
	Bundle     string `json:"bundle"`
}

type classReport struct {
	Class     string `json:"class"`
	Source    string `json:"source"`
	EventType string `json:"event_type"`
}

func Seal(incident, reason string, bundle []byte) ([]byte, error) {
	if !ValidIncident(incident) || !ValidReason(reason) || len(bundle) == 0 || len(bundle) > maxArchive {
		return nil, ErrRejected
	}
	sum := sha256.Sum256(bundle)
	body, err := json.Marshal(bundleEnvelope{
		IncidentID: incident,
		Reason:     reason,
		SHA256:     hex.EncodeToString(sum[:]),
		Bundle:     base64.StdEncoding.EncodeToString(bundle),
	})
	if err != nil || len(body) > 2<<20 {
		return nil, ErrRejected
	}
	return body, nil
}

func Open(raw []byte) (incident, reason string, bundle []byte, err error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return "", "", nil, ErrRejected
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env bundleEnvelope
	if err = dec.Decode(&env); err != nil || dec.More() {
		return "", "", nil, ErrRejected
	}
	if !ValidIncident(env.IncidentID) || !ValidReason(env.Reason) || len(env.SHA256) != sha256.Size*2 {
		return "", "", nil, ErrRejected
	}
	bundle, err = base64.StdEncoding.DecodeString(env.Bundle)
	if err != nil || len(bundle) == 0 || len(bundle) > maxArchive {
		return "", "", nil, ErrRejected
	}
	sum := sha256.Sum256(bundle)
	if hex.EncodeToString(sum[:]) != env.SHA256 {
		return "", "", nil, ErrRejected
	}
	return env.IncidentID, env.Reason, bundle, nil
}

func SealClass(class, source, eventType string) ([]byte, error) {
	if (class != ClassSuspicious && class != ClassExfiltrate) || !label(source) || !label(eventType) {
		return nil, ErrRejected
	}
	body, err := json.Marshal(classReport{Class: class, Source: source, EventType: eventType})
	if err != nil || len(body) > 1024 {
		return nil, ErrRejected
	}
	return body, nil
}

func OpenClass(raw []byte) (class, source, eventType string, err error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return "", "", "", ErrRejected
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var report classReport
	if err = dec.Decode(&report); err != nil || dec.More() {
		return "", "", "", ErrRejected
	}
	if (report.Class != ClassSuspicious && report.Class != ClassExfiltrate) || !label(report.Source) || !label(report.EventType) {
		return "", "", "", ErrRejected
	}
	return report.Class, report.Source, report.EventType, nil
}

func label(value string) bool {
	if value == "" || len(value) > 64 || strings.ContainsAny(value, "\r\n\t /\\") {
		return false
	}
	return true
}
