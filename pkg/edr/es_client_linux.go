//go:build linux

package edr

// Linux EDR sensor using fanotify (exec/file events) and the netlink proc connector (exit events).
//
// Requires Linux 5.0+ for FAN_OPEN_EXEC / FAN_OPEN_EXEC_PERM.
// Auth interception (FAN_CLASS_CONTENT) requires CAP_SYS_ADMIN; falls back to notify-only.

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExit     = 0x80000000
)

// fanotifyAuthMsg holds the descriptors needed to respond to a FAN_OPEN_EXEC_PERM event.
// Stored in ProcessEvent.Msg; caller must pass it back to RespondAuth.
type fanotifyAuthMsg struct {
	fanotifyFd int
	eventFd    int
}

// ESConsumer monitors process and file events via fanotify and the netlink proc connector.
type ESConsumer struct {
	fanotifyFd int
	events     chan<- ProcessEvent
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	authMode   bool // true when FAN_CLASS_CONTENT succeeded (blocking exec interception available)
}

// NewESConsumer creates a fanotify-backed sensor.
// Tries FAN_CLASS_CONTENT (blocking, requires CAP_SYS_ADMIN) first; falls back to
// FAN_CLASS_NOTIF (notify-only) if denied.
func NewESConsumer(eventChannel chan<- ProcessEvent) (*ESConsumer, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE,
	)
	authMode := true
	if err != nil {
		fd, err = unix.FanotifyInit(
			unix.FAN_CLOEXEC|unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK,
			unix.O_RDONLY|unix.O_LARGEFILE,
		)
		if err != nil {
			return nil, fmt.Errorf("fanotify_init: %w", err)
		}
		authMode = false
	}
	return &ESConsumer{fanotifyFd: fd, events: eventChannel, authMode: authMode}, nil
}

// Subscribe arms the fanotify watch on the root mount and starts the event loops.
// The events []uint32 parameter is ignored — darwin ES event type constants have no
// direct fanotify equivalent; we arm all relevant events unconditionally.
func (c *ESConsumer) Subscribe(_ []uint32) error {
	mask := uint64(unix.FAN_OPEN_EXEC | unix.FAN_CLOSE_WRITE)
	if c.authMode {
		mask |= unix.FAN_OPEN_EXEC_PERM
	}
	if err := unix.FanotifyMark(
		c.fanotifyFd,
		unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
		mask,
		unix.AT_FDCWD, "/",
	); err != nil {
		return fmt.Errorf("fanotify_mark /: %w (requires Linux 5.0+ and CAP_SYS_ADMIN)", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(2)
	go c.readFanotify(ctx)
	go c.readProcConnector(ctx)
	return nil
}

// RespondAuth allows or denies an intercepted FAN_OPEN_EXEC_PERM event.
// Must be called exactly once per EventAuthExec event; it closes the event fd.
func (c *ESConsumer) RespondAuth(event ProcessEvent, allow bool, _ bool) error {
	if event.Msg == nil {
		return nil
	}
	msg := (*fanotifyAuthMsg)(event.Msg)
	defer unix.Close(msg.eventFd)

	var resp uint32 = unix.FAN_DENY
	if allow {
		resp = unix.FAN_ALLOW
	}
	// fanotify_response: { __s32 fd; __u32 response; }
	buf := make([]byte, 8)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(msg.eventFd))
	binary.NativeEndian.PutUint32(buf[4:8], resp)
	_, err := unix.Write(msg.fanotifyFd, buf)
	return err
}

// readFanotify polls the fanotify fd and dispatches events.
func (c *ESConsumer) readFanotify(ctx context.Context) {
	defer c.wg.Done()

	const metaSize = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(c.fanotifyFd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Poll(pollFds, 100)
		if err != nil || n == 0 {
			continue
		}

		n, err = unix.Read(c.fanotifyFd, buf)
		if err != nil || n < metaSize {
			continue
		}

		for offset := 0; offset+metaSize <= n; {
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
				break
			}
			evLen := int(meta.Event_len)
			if evLen < metaSize {
				break
			}
			offset += evLen

			if meta.Fd < 0 { // FAN_NOFD: queue overflow marker
				continue
			}
			c.dispatchFanotifyEvent(meta)
		}
	}
}

func (c *ESConsumer) dispatchFanotifyEvent(meta *unix.FanotifyEventMetadata) {
	fd := int(meta.Fd)
	pid := int(meta.Pid)

	execPath := fdReadlink(fd)
	ppid, uid := procInfoFromPID(pid)

	var evType EventType
	var msgPtr unsafe.Pointer

	switch {
	case meta.Mask&unix.FAN_OPEN_EXEC_PERM != 0:
		evType = EventAuthExec
		// Ownership of fd transfers to fanotifyAuthMsg; RespondAuth closes it.
		msgPtr = unsafe.Pointer(&fanotifyAuthMsg{fanotifyFd: c.fanotifyFd, eventFd: fd})
		fd = -1
	case meta.Mask&unix.FAN_OPEN_EXEC != 0:
		evType = EventNotifyExec
		defer unix.Close(fd)
	case meta.Mask&unix.FAN_CLOSE_WRITE != 0:
		evType = EventNotifyCreate
		defer unix.Close(fd)
	default:
		unix.Close(fd)
		return
	}
	_ = fd // suppress unused-after-reassign warning for auth path

	select {
	case c.events <- ProcessEvent{
		Type:      evType,
		Timestamp: time.Now(),
		PID:       pid,
		PPID:      ppid,
		ExecPath:  execPath,
		UID:       uid,
		Msg:       msgPtr,
	}:
	default:
		// Channel full: drop notify events; for auth events we must still respond
		// to avoid blocking the kernel indefinitely.
		if evType == EventAuthExec {
			msg := (*fanotifyAuthMsg)(msgPtr)
			buf := make([]byte, 8)
			binary.NativeEndian.PutUint32(buf[0:4], uint32(msg.eventFd))
			binary.NativeEndian.PutUint32(buf[4:8], unix.FAN_ALLOW)
			unix.Write(c.fanotifyFd, buf) //nolint:errcheck
			unix.Close(msg.eventFd)
		}
	}
}

// readProcConnector subscribes to PROC_EVENT_EXIT via the kernel proc connector
// and emits EventNotifyExit events. Silently returns if netlink is unavailable.
func (c *ESConsumer) readProcConnector(ctx context.Context) {
	defer c.wg.Done()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		return
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: cnIdxProc,
	}); err != nil {
		return
	}
	if err := nlSendProcSubscribe(fd); err != nil {
		return
	}

	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Poll(pollFds, 100)
		if err != nil || n == 0 {
			continue
		}

		n, _, err = unix.Recvfrom(fd, buf, 0)
		if err != nil || n < unix.SizeofNlMsghdr {
			continue
		}
		c.parseProcConnectorMsgs(buf[:n])
	}
}

// nlSendProcSubscribe sends PROC_CN_MCAST_LISTEN to begin receiving proc events.
func nlSendProcSubscribe(fd int) error {
	// nlmsghdr(16) + cn_msg header(20) + uint32 op(4) = 40 bytes
	const totalLen = unix.SizeofNlMsghdr + 20 + 4
	buf := make([]byte, totalLen)

	binary.NativeEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.NativeEndian.PutUint16(buf[4:6], unix.NLMSG_DONE)
	// nlmsg_flags, nlmsg_seq, nlmsg_pid = 0

	off := unix.SizeofNlMsghdr
	binary.NativeEndian.PutUint32(buf[off:off+4], cnIdxProc)          // cb_id.idx
	binary.NativeEndian.PutUint32(buf[off+4:off+8], cnValProc)        // cb_id.val
	// seq, ack = 0
	binary.NativeEndian.PutUint16(buf[off+16:off+18], 4)              // len = sizeof(op)
	// flags = 0
	binary.NativeEndian.PutUint32(buf[off+20:off+24], procCnMcastListen)

	return unix.Send(fd, buf, 0)
}

func (c *ESConsumer) parseProcConnectorMsgs(buf []byte) {
	// Each Recvfrom on SOCK_DGRAM returns one netlink datagram; loop handles
	// the rare case of multiple messages in a single buffer.
	const nlHdrSize = 16 // sizeof(struct nlmsghdr)
	for len(buf) >= nlHdrSize {
		nlLen := int(binary.NativeEndian.Uint32(buf[0:4]))
		if nlLen < nlHdrSize || nlLen > len(buf) {
			break
		}
		c.handleCnMsg(buf[nlHdrSize:nlLen])
		aligned := (nlLen + 3) &^ 3
		if aligned >= len(buf) {
			break
		}
		buf = buf[aligned:]
	}
}

func (c *ESConsumer) handleCnMsg(data []byte) {
	// cn_msg: idx(4)+val(4)+seq(4)+ack(4)+len(2)+flags(2) = 20 bytes
	if len(data) < 20 {
		return
	}
	if binary.NativeEndian.Uint32(data[0:4]) != cnIdxProc ||
		binary.NativeEndian.Uint32(data[4:8]) != cnValProc {
		return
	}
	// proc_event: what(4)+cpu(4)+timestamp_ns(8) = 16 bytes, then event_data
	evData := data[20:]
	if len(evData) < 16 {
		return
	}
	if binary.NativeEndian.Uint32(evData[0:4]) != procEventExit {
		return
	}
	// exit_proc_event: process_pid(4)+process_tgid(4)+exit_code(4)+exit_signal(4)+parent_pid(4)+parent_tgid(4)
	if len(evData) < 16+24 {
		return
	}
	exitData := evData[16:]
	pid := int(int32(binary.NativeEndian.Uint32(exitData[0:4])))
	ppid := int(int32(binary.NativeEndian.Uint32(exitData[16:20])))

	select {
	case c.events <- ProcessEvent{
		Type:      EventNotifyExit,
		Timestamp: time.Now(),
		PID:       pid,
		PPID:      ppid,
	}:
	default:
	}
}

// fdReadlink resolves an open fd to its path via /proc/self/fd.
func fdReadlink(fd int) string {
	path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	return path
}

// procInfoFromPID reads PPID and real UID from /proc/<pid>/status.
func procInfoFromPID(pid int) (ppid int, uid uint32) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "PPid:"):
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), "%d", &ppid)
		case strings.HasPrefix(line, "Uid:"):
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "Uid:")), "%d", &uid)
		}
	}
	return
}
