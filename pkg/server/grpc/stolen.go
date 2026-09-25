package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/display"
	"aftersec/pkg/response"
	"aftersec/pkg/server/stolen"
)

// StolenMinter re-delivers a stolen mark that an operator already recorded.
type StolenMinter interface {
	MintDelivered(context.Context, string, string, response.Action) (string, error)
}

func (s *Server) SetStolen(reg *stolen.Registry, minter StolenMinter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stolen = reg
	s.stolenMinter = minter
}

func (s *Server) stolenAction(tenant, endpoint string) string {
	s.mu.RLock()
	reg := s.stolen
	s.mu.RUnlock()
	if reg == nil {
		return ""
	}
	marked, clear := reg.State(tenant, endpoint)
	if marked {
		return "MARK_STOLEN"
	}
	if clear {
		return "CLEAR_STOLEN"
	}
	return ""
}

func (s *Server) deliverStolen(ctx context.Context, tenant, endpoint string, ch chan *grpcapi.ServerCommand) {
	actionName := s.stolenAction(tenant, endpoint)
	if actionName == "" {
		return
	}
	s.mu.RLock()
	minter := s.stolenMinter
	s.mu.RUnlock()
	if minter == nil {
		return
	}
	action := response.ActionMarkStolen
	if actionName == "CLEAR_STOLEN" {
		action = response.ActionClearStolen
	}
	token, err := minter.MintDelivered(ctx, tenant, endpoint, action)
	if err != nil {
		log.Printf("stolen mark delivery failed endpoint=%s: %v", endpoint, err)
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
		log.Printf("stolen mark delivery queued full endpoint=%s", endpoint)
	}
}

// takeStolenCamera stores a camera frame only for an endpoint an operator
// marked stolen, and returns a payload that contains no image bytes.
func (s *Server) takeStolenCamera(event *grpcapi.ClientEvent) (string, bool) {
	if event == nil || len(event.Payload) == 0 || len(event.Payload) > 2<<20 {
		return `{"stored":false}`, false
	}
	frame, err := display.OpenEnvelope([]byte(event.Payload))
	if err != nil {
		return `{"stored":false}`, false
	}
	s.mu.RLock()
	reg := s.stolen
	frames := s.displayFrames
	s.mu.RUnlock()
	if reg == nil || frames == nil || event.TenantId == "" || event.HardwareId == "" {
		return `{"stored":false}`, false
	}
	marked, _ := reg.State(event.TenantId, event.HardwareId)
	if !marked {
		log.Printf("stolen camera rejected endpoint=%s: device is not marked stolen", event.HardwareId)
		return `{"stored":false}`, false
	}
	sum := sha256.Sum256(frame)
	id := hex.EncodeToString(sum[:16])
	if err = frames.Save(event.TenantId, event.HardwareId, id, frame); err != nil {
		log.Printf("stolen camera rejected endpoint=%s: %v", event.HardwareId, err)
		return `{"stored":false}`, false
	}
	log.Printf("stolen camera stored endpoint=%s id=%s bytes=%d", event.HardwareId, id, len(frame))
	return fmt.Sprintf(`{"stored":true,"id":"%s","sha256":"%s","bytes":%d}`, id, hex.EncodeToString(sum[:]), len(frame)), true
}
