//go:build darwin || linux

package dnsanalytics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONLSourceEmitsAttributedDNSQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.jsonl")
	line := fmt.Sprintf(`{"kind":"dns_query","pid":42,"process":"/bin/test","domain":"Example.COM","timestamp":%d}`+"\n", time.Now().Unix())
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewJSONLSource(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan Query, 1)
	go func() {
		_ = source.Watch(ctx, func(query Query) error {
			got <- query
			cancel()
			return nil
		})
	}()
	select {
	case query := <-got:
		if query.PID != 42 || query.Domain != "Example.COM" {
			t.Fatalf("query = %+v", query)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DNS query")
	}
}
