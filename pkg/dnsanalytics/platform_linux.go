//go:build linux

package dnsanalytics

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const linuxDNSDomainBytes = 254

type linuxDNSEvent struct {
	PID     uint32
	UID     uint32
	Process [16]byte
	Domain  [linuxDNSDomainBytes]byte
}

type linuxEBPFDNSSource struct {
	objectPath string
}

func NewPlatformSource(_, objectPath string) (Source, error) {
	info, err := os.Stat(objectPath)
	if err != nil {
		return nil, fmt.Errorf("stat DNS eBPF object: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("DNS eBPF object permissions are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, fmt.Errorf("DNS eBPF object owner is untrusted")
	}
	return &linuxEBPFDNSSource{objectPath: objectPath}, nil
}

func (s *linuxEBPFDNSSource) Watch(ctx context.Context, emit func(Query) error) error {
	if s == nil || s.objectPath == "" || emit == nil {
		return fmt.Errorf("Linux DNS eBPF source is not configured")
	}
	spec, err := ebpf.LoadCollectionSpec(s.objectPath)
	if err != nil {
		return fmt.Errorf("load DNS eBPF spec: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load DNS eBPF collection: %w", err)
	}
	defer collection.Close()
	events := collection.Maps["events"]
	program := collection.Programs["trace_udp_sendmsg"]
	if events == nil || program == nil {
		return fmt.Errorf("DNS eBPF object is missing required map or program")
	}
	probe, err := link.Kprobe("udp_sendmsg", program, nil)
	if err != nil {
		return fmt.Errorf("attach udp_sendmsg DNS probe: %w", err)
	}
	defer probe.Close()
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("open DNS event ring: %w", err)
	}
	defer reader.Close()
	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()
	for {
		record, readErr := reader.Read()
		if readErr != nil {
			if errors.Is(readErr, ringbuf.ErrClosed) && ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read DNS eBPF event: %w", readErr)
		}
		var event linuxDNSEvent
		if err := binary.Read(bytesReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode DNS eBPF event: %w", err)
		}
		query := Query{
			PID:     int(event.PID),
			Process: cString(event.Process[:]),
			Domain:  cString(event.Domain[:]),
		}
		if err := emit(query); err != nil {
			return err
		}
	}
}

func bytesReader(data []byte) io.Reader { return &byteReader{data: data} }

type byteReader struct{ data []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func cString(value []byte) string {
	for i, b := range value {
		if b == 0 {
			return string(value[:i])
		}
	}
	return string(value)
}
