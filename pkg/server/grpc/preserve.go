package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/preserve"
	"aftersec/pkg/response"
	serverpreserve "aftersec/pkg/server/preserve"
)

// PreserveMinter re-delivers a preserve mark an operator already recorded.
type PreserveMinter interface {
	MintPreserve(context.Context, string, string, string, string) (string, error)
	MintDelivered(context.Context, string, string, response.Action) (string, error)
}

func (s *Server) SetPreserve(reg *serverpreserve.Registry, store *serverpreserve.Store, minter PreserveMinter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preserveReg = reg
	s.preserveStore = store
	s.preserveMinter = minter
}

func (s *Server) preserveAction(tenant, endpoint string) string {
	s.mu.RLock()
	reg := s.preserveReg
	s.mu.RUnlock()
	if reg == nil {
		return ""
	}
	if _, _, ok := reg.State(tenant, endpoint); ok {
		return "PRESERVE"
	}
	return ""
}

func (s *Server) deliverPreserve(ctx context.Context, tenant, endpoint string, ch chan *grpcapi.ServerCommand) {
	s.mu.RLock()
	reg := s.preserveReg
	minter := s.preserveMinter
	s.mu.RUnlock()
	if reg == nil || minter == nil {
		return
	}
	reason, incident, ok := reg.State(tenant, endpoint)
	if !ok {
		return
	}
	token, err := minter.MintPreserve(ctx, tenant, endpoint, reason, incident)
	if err != nil {
		log.Printf("preserve delivery failed endpoint=%s: %v", endpoint, err)
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return
	}
	cmd := &grpcapi.ServerCommand{CommandId: hex.EncodeToString(id[:]), Action: "REMOTE_ACTION", Payload: token}
	select {
	case ch <- cmd:
	default:
		log.Printf("preserve delivery queued full endpoint=%s", endpoint)
	}
}

// takePreserve stores an archive only when the operator mark matches the
// incident id, and returns a payload that contains no archive bytes.
func (s *Server) takePreserve(event *grpcapi.ClientEvent) (string, bool) {
	if event == nil || len(event.Payload) == 0 || len(event.Payload) > 2<<20 {
		return `{"stored":false}`, false
	}
	incident, reason, bundle, err := preserve.Open([]byte(event.Payload))
	if err != nil {
		return `{"stored":false}`, false
	}
	s.mu.RLock()
	reg := s.preserveReg
	store := s.preserveStore
	s.mu.RUnlock()
	if reg == nil || store == nil || event.TenantId == "" || event.HardwareId == "" {
		return `{"stored":false}`, false
	}
	markedReason, markedIncident, ok := reg.State(event.TenantId, event.HardwareId)
	if !ok || markedReason != reason || markedIncident != incident {
		log.Printf("preserve rejected endpoint=%s: mark does not match", event.HardwareId)
		return `{"stored":false}`, false
	}
	if err = store.Save(event.TenantId, event.HardwareId, incident, bundle); err != nil {
		log.Printf("preserve rejected endpoint=%s: %v", event.HardwareId, err)
		return `{"stored":false}`, false
	}
	sum := sha256.Sum256(bundle)
	log.Printf("preserve stored endpoint=%s incident=%s bytes=%d", event.HardwareId, incident, len(bundle))
	return fmt.Sprintf(`{"stored":true,"incident_id":"%s","sha256":"%s","bytes":%d}`, incident, hex.EncodeToString(sum[:]), len(bundle)), true
}

func (s *Server) takePreserveClass(event *grpcapi.ClientEvent) string {
	if event == nil || len(event.Payload) == 0 || len(event.Payload) > 1024 {
		return `{"stored":false}`
	}
	class, source, eventType, err := preserve.OpenClass([]byte(event.Payload))
	if err != nil {
		return `{"stored":false}`
	}
	log.Printf("preserve class endpoint=%s class=%s source=%s event=%s", event.HardwareId, class, source, eventType)
	return fmt.Sprintf(`{"stored":true,"class":"%s","source":"%s","event_type":"%s"}`, class, source, eventType)
}
