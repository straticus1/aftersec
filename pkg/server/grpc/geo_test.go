package grpcserver

import (
	"context"
	"net"
	"net/netip"
	"testing"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/geoip"
	"google.golang.org/grpc/peer"
)

func TestFlowAddressReadsEitherField(t *testing.T) {
	if got := flowAddress(`{"remoteAddress":"1.1.1.1"}`); got != "1.1.1.1" {
		t.Fatalf("%s", got)
	}
	if got := flowAddress(`{"remote_ip":"8.8.8.8"}`); got != "8.8.8.8" {
		t.Fatalf("%s", got)
	}
	if got := flowAddress(`{"ProcessName":"curl","RemoteAddress":"9.9.9.9","RemotePort":443}`); got != "9.9.9.9" {
		t.Fatalf("daemon flow: %s", got)
	}
	if flowAddress("not-json") != "" || flowAddress(`{"path":"/bin/ls"}`) != "" {
		t.Fatal("unrelated payload returned an address")
	}
}

func TestHeartbeatLogsPeerPlaceWithoutBlocking(t *testing.T) {
	s := &Server{}
	s.SetGeoResolver(geoip.NewResolver(geoipMap{netip.MustParseAddr("1.1.1.1"): {Country: "US", NetName: "EXAMPLE-NET"}}, nil))
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}})
	resp, err := s.Heartbeat(ctx, &grpcapi.HeartbeatRequest{TenantId: "org", HardwareId: "hw", Timestamp: 1_700_000_000})
	if err != nil || resp == nil || resp.Action != "NONE" {
		t.Fatalf("%v %+v", err, resp)
	}
}

type geoipMap map[netip.Addr]geoip.Record

func (m geoipMap) Lookup(addr netip.Addr) (geoip.Record, error) { return m[addr], nil }
