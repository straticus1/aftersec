package response

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type AuditEvent struct {
	CommandID  string    `json:"command_id"`
	TenantID   string    `json:"tenant_id"`
	EndpointID string    `json:"endpoint_id"`
	Action     Action    `json:"action"`
	Status     string    `json:"status"`
	Timestamp  time.Time `json:"timestamp"`
}
type auditRecord struct {
	Event    AuditEvent
	Previous [sha256.Size]byte
	Hash     [sha256.Size]byte
}
type AuditJournal struct {
	mu      sync.RWMutex
	max     int
	records []auditRecord
}

func NewAuditJournal(max int) *AuditJournal { return &AuditJournal{max: max} }

// Append creates an in-memory hash-linked audit record. Production persistence
// can wrap the same record contract in PostgreSQL append-only/RLS storage.
// Threats: mutation and deletion are detected; host compromise and durable storage are outside this in-memory implementation.
func (j *AuditJournal) Append(e AuditEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.max <= 0 || len(j.records) >= j.max {
		return fmt.Errorf("audit journal full")
	}
	if e.CommandID == "" || e.TenantID == "" || e.EndpointID == "" || e.Status == "" || e.Timestamp.IsZero() || !validClaims(ActionClaims{ID: e.CommandID, TenantID: e.TenantID, EndpointID: e.EndpointID, Action: e.Action, ExpiresAt: e.Timestamp}) {
		return fmt.Errorf("invalid audit event")
	}
	var prev [sha256.Size]byte
	if len(j.records) > 0 {
		prev = j.records[len(j.records)-1].Hash
	}
	h, err := auditHash(prev, e)
	if err != nil {
		return err
	}
	j.records = append(j.records, auditRecord{Event: e, Previous: prev, Hash: h})
	return nil
}
func (j *AuditJournal) Verify() error {
	j.mu.RLock()
	defer j.mu.RUnlock()
	var prev [sha256.Size]byte
	for i, r := range j.records {
		if subtle.ConstantTimeCompare(prev[:], r.Previous[:]) != 1 {
			return fmt.Errorf("audit chain gap at %d", i)
		}
		h, err := auditHash(prev, r.Event)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(h[:], r.Hash[:]) != 1 {
			return fmt.Errorf("audit tampering at %d", i)
		}
		prev = r.Hash
	}
	return nil
}
func auditHash(prev [sha256.Size]byte, e AuditEvent) ([sha256.Size]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode audit event: %w", err)
	}
	h := sha256.New()
	if _, err = h.Write(prev[:]); err != nil {
		return [sha256.Size]byte{}, err
	}
	if _, err = h.Write(b); err != nil {
		return [sha256.Size]byte{}, err
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
