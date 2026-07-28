//go:build linux

package netsensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type LinuxEBPFBackend struct {
	objectPath string
}

func NewPlatformBackend(_ string, objectPath string) (Backend, error) {
	info, err := os.Stat(objectPath)
	if err != nil {
		return nil, fmt.Errorf("stat network eBPF object: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("network eBPF object permissions are unsafe")
	}
	return &LinuxEBPFBackend{objectPath: objectPath}, nil
}

type linuxFlowEvent struct {
	TimestampNS uint64
	PID         uint32
	UID         uint32
	LocalPort   uint16
	RemotePort  uint16
	Family      uint8
	Protocol    uint8
	_           [2]byte
	Process     [16]byte
	LocalAddr   [16]byte
	RemoteAddr  [16]byte
}

// Run loads a bounded CO-RE object, attaches only the connect tracepoint, and
// consumes its ring buffer. Threats: attach, decode, attribution, and ring
// buffer failures are returned to the required-sensor supervisor.
func (b *LinuxEBPFBackend) Run(ctx context.Context, emit func(Flow) error) error {
	if b == nil || b.objectPath == "" || emit == nil {
		return fmt.Errorf("Linux eBPF network backend is not configured")
	}
	spec, err := ebpf.LoadCollectionSpec(b.objectPath)
	if err != nil {
		return fmt.Errorf("load network eBPF spec: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load network eBPF collection: %w", err)
	}
	defer collection.Close()
	events := collection.Maps["events"]
	if events == nil {
		return fmt.Errorf("network eBPF object is missing events")
	}
	var attached []link.Link
	defer func() {
		for _, item := range attached {
			item.Close()
		}
	}()
	probes := []struct {
		program, symbol string
		ret             bool
	}{
		{"enter_tcp_v4_connect", "tcp_v4_connect", false},
		{"exit_tcp_v4_connect", "tcp_v4_connect", true},
		{"enter_tcp_v6_connect", "tcp_v6_connect", false},
		{"exit_tcp_v6_connect", "tcp_v6_connect", true},
	}
	for _, probe := range probes {
		program := collection.Programs[probe.program]
		if program == nil {
			return fmt.Errorf("network eBPF object is missing %s", probe.program)
		}
		var item link.Link
		if probe.ret {
			item, err = link.Kretprobe(probe.symbol, program, nil)
		} else {
			item, err = link.Kprobe(probe.symbol, program, nil)
		}
		if err != nil {
			return fmt.Errorf("attach %s: %w", probe.program, err)
		}
		attached = append(attached, item)
	}
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("open network eBPF ring buffer: %w", err)
	}
	defer reader.Close()
	go func() {
		<-ctx.Done()
		reader.Close()
	}()
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read network eBPF event: %w", err)
		}
		var raw linuxFlowEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			return fmt.Errorf("decode network eBPF event: %w", err)
		}
		flow, err := raw.flow()
		if err != nil {
			return err
		}
		if err := emit(flow); err != nil {
			return err
		}
	}
}

func (e linuxFlowEvent) flow() (Flow, error) {
	process := strings.TrimRight(string(e.Process[:]), "\x00")
	var local, remote net.IP
	switch e.Family {
	case 2:
		local, remote = net.IP(e.LocalAddr[:4]), net.IP(e.RemoteAddr[:4])
	case 10:
		local, remote = net.IP(e.LocalAddr[:]), net.IP(e.RemoteAddr[:])
	default:
		return Flow{}, ErrInvalidFlow
	}
	protocol := "tcp"
	if e.Protocol == 17 {
		protocol = "udp"
	} else if e.Protocol != 6 {
		return Flow{}, ErrInvalidFlow
	}
	at := time.Now()
	return Flow{
		ProcessID:     int(e.PID),
		ProcessName:   process,
		UserID:        e.UID,
		LocalAddress:  local.String(),
		LocalPort:     e.LocalPort,
		RemoteAddress: remote.String(),
		RemotePort:    e.RemotePort,
		Protocol:      protocol,
		StartedAt:     at,
		EndedAt:       at,
		Attribution:   AttributionExact,
	}, nil
}
