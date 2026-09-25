package grpcserver

import (
	"strings"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/fleetcorrelation"
)

func TestStreamEventsFleetRejectionIsNotAcknowledged(t *testing.T) {
	s := &Server{eventQueue: make(chan *grpcapi.ClientEvent, 4)}
	sink := &fleetcorrelation.MemorySink{}
	s.SetFleetCorrelation(fleetcorrelation.NewEngine(time.Hour, 10, 2), sink)
	hash := strings.Repeat("ab", 32)
	stream := &mockStreamEventsServer{events: []*grpcapi.ClientEvent{{
		TenantId: "org", HardwareId: "host", Timestamp: time.Now().Unix(),
		EventType: "allow", Payload: `{"path":"/bin/ls","identity":{"SHA256":"abcd"}}`,
	}}}
	if err := s.StreamEvents(stream); err != nil {
		t.Fatal(err)
	}
	if stream.ack == nil || stream.ack.EventsProcessed != 0 {
		t.Fatalf("%+v", stream.ack)
	}
	good := &mockStreamEventsServer{events: []*grpcapi.ClientEvent{{
		TenantId: "org", HardwareId: "host", Timestamp: time.Now().Unix(),
		EventType: "allow", Payload: `{"path":"/bin/ls","identity":{"SHA256":"` + hash + `"}}`,
	}}}
	if err := s.StreamEvents(good); err != nil {
		t.Fatal(err)
	}
	if good.ack == nil || good.ack.EventsProcessed != 1 {
		t.Fatalf("%+v", good.ack)
	}
}
