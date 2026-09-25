package grpcserver

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"strings"

	"aftersec/pkg/geoip"
	"google.golang.org/grpc/peer"
)

func (s *Server) SetGeoResolver(resolver *geoip.Resolver) {
	s.mu.Lock()
	s.geo = resolver
	s.mu.Unlock()
}

func (s *Server) geoResolver() *geoip.Resolver {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.geo
}

func (s *Server) logPeerPlace(ctx context.Context, endpoint string) {
	resolver := s.geoResolver()
	if resolver == nil {
		return
	}
	ip := peerAddress(ctx)
	if ip == "" {
		return
	}
	place, err := resolver.Lookup(ctx, ip)
	if err != nil {
		log.Printf("endpoint %s location unavailable: %v", endpoint, err)
		return
	}
	log.Printf("endpoint %s %s", endpoint, place.Glance())
}

func (s *Server) logFlowPlace(endpoint, payload string) {
	resolver := s.geoResolver()
	if resolver == nil {
		return
	}
	ip := flowAddress(payload)
	if ip == "" {
		return
	}
	place, err := resolver.Lookup(context.Background(), ip)
	if err != nil {
		log.Printf("flow endpoint=%s remote=%s location unavailable: %v", endpoint, ip, err)
		return
	}
	log.Printf("flow endpoint=%s %s", endpoint, place.Glance())
}

func peerAddress(ctx context.Context) string {
	value, ok := peer.FromContext(ctx)
	if !ok || value == nil || value.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(value.Addr.String())
	if err != nil {
		return value.Addr.String()
	}
	return host
}

func flowAddress(payload string) string {
	var body map[string]any
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return ""
	}
	// netsensor.Flow has no json tags, so the daemon emits RemoteAddress.
	// Sinks that tag the field use remoteAddress or remote_ip.
	for _, key := range []string{"remoteAddress", "RemoteAddress", "remote_ip"} {
		value, ok := body[key].(string)
		if !ok {
			continue
		}
		if ip := strings.TrimSpace(value); ip != "" {
			return ip
		}
	}
	return ""
}
