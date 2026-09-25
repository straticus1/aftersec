package grpcserver

import (
	"testing"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/preserve"
	serverpreserve "aftersec/pkg/server/preserve"
)

func TestTakePreserveStoresOnlyAMatchingMark(t *testing.T) {
	dir := t.TempDir()
	reg, err := serverpreserve.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := serverpreserve.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = reg.Mark("org", "HW-host", "lost", "INC-10001"); err != nil {
		t.Fatal(err)
	}
	bundle := []byte("preserve-archive")
	body, err := preserve.Seal("INC-10001", "lost", bundle)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{preserveReg: reg, preserveStore: store}
	summary, stored := s.takePreserve(&grpcapi.ClientEvent{TenantId: "org", HardwareId: "HW-host", EventType: "preserve_bundle", Payload: string(body)})
	if !stored || summary == string(body) {
		t.Fatal(summary, stored)
	}
	other, err := preserve.Seal("INC-10001", "breached", bundle)
	if err != nil {
		t.Fatal(err)
	}
	summary, stored = s.takePreserve(&grpcapi.ClientEvent{TenantId: "org", HardwareId: "HW-host", EventType: "preserve_bundle", Payload: string(other)})
	if stored {
		t.Fatal("mismatched reason stored")
	}
	notice, err := preserve.SealClass(preserve.ClassExfiltrate, "dns_sensor", "process_dns_query")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.takePreserveClass(&grpcapi.ClientEvent{HardwareId: "HW-host", Payload: string(notice)}); got == `{"stored":false}` {
		t.Fatal(got)
	}
	if got := s.takePreserveClass(&grpcapi.ClientEvent{Payload: `{"class":"other","source":"dns_sensor","event_type":"process_dns_query"}`}); got != `{"stored":false}` {
		t.Fatal(got)
	}
}
