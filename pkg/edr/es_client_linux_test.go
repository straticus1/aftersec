//go:build linux

package edr

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// buildCnExitMsg constructs a cn_msg payload (the bytes handleCnMsg receives,
// i.e. everything after the nlmsghdr) carrying a PROC_EVENT_EXIT.
func buildCnExitMsg(idx, val, what uint32, pid, ppid int32) []byte {
	// cn_msg(20) + proc_event header(16) + exit_proc_event(24)
	buf := make([]byte, 60)
	binary.NativeEndian.PutUint32(buf[0:4], idx)   // cb_id.idx
	binary.NativeEndian.PutUint32(buf[4:8], val)   // cb_id.val
	binary.NativeEndian.PutUint16(buf[16:18], 40)  // len
	binary.NativeEndian.PutUint32(buf[20:24], what)
	// cpu(4) + timestamp_ns(8) left zero
	exit := buf[36:]
	binary.NativeEndian.PutUint32(exit[0:4], uint32(pid))    // process_pid
	binary.NativeEndian.PutUint32(exit[4:8], uint32(pid))    // process_tgid
	// exit_code(4) + exit_signal(4) left zero
	binary.NativeEndian.PutUint32(exit[16:20], uint32(ppid)) // parent_pid
	binary.NativeEndian.PutUint32(exit[20:24], uint32(ppid)) // parent_tgid
	return buf
}

// wrapNlMsg prepends an nlmsghdr to a cn_msg payload.
func wrapNlMsg(payload []byte) []byte {
	buf := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(buf[0:4], uint32(len(buf))) // nlmsg_len
	binary.NativeEndian.PutUint16(buf[4:6], 0x3)              // NLMSG_DONE
	copy(buf[16:], payload)
	return buf
}

func TestHandleCnMsg_ExitEvent(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	c := &ESConsumer{events: ch}

	c.handleCnMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 1234, 1))

	select {
	case ev := <-ch:
		if ev.Type != EventNotifyExit {
			t.Errorf("expected EventNotifyExit, got %q", ev.Type)
		}
		if ev.PID != 1234 {
			t.Errorf("expected PID 1234, got %d", ev.PID)
		}
		if ev.PPID != 1 {
			t.Errorf("expected PPID 1, got %d", ev.PPID)
		}
	default:
		t.Fatal("expected an exit event on the channel")
	}
}

func TestHandleCnMsg_IgnoresNonExitEvents(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	c := &ESConsumer{events: ch}

	const procEventFork = 0x00000001
	c.handleCnMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventFork, 1234, 1))

	if len(ch) != 0 {
		t.Error("fork events must not be emitted")
	}
}

func TestHandleCnMsg_IgnoresWrongConnectorID(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	c := &ESConsumer{events: ch}

	c.handleCnMsg(buildCnExitMsg(99, 99, procEventExit, 1234, 1))

	if len(ch) != 0 {
		t.Error("messages from other connectors must be ignored")
	}
}

func TestHandleCnMsg_ShortBuffersAreSafe(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	c := &ESConsumer{events: ch}

	for size := 0; size < 60; size++ {
		c.handleCnMsg(make([]byte, size))
	}
	if len(ch) != 0 {
		t.Error("truncated messages must not produce events")
	}
}

func TestHandleCnMsg_FullChannelDoesNotBlock(t *testing.T) {
	ch := make(chan ProcessEvent) // unbuffered, no reader
	c := &ESConsumer{events: ch}

	done := make(chan struct{})
	go func() {
		c.handleCnMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 1, 1))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleCnMsg blocked on a full channel; it must drop instead")
	}
}

func TestParseProcConnectorMsgs_SingleDatagram(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	c := &ESConsumer{events: ch}

	c.parseProcConnectorMsgs(wrapNlMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 4321, 100)))

	select {
	case ev := <-ch:
		if ev.PID != 4321 || ev.PPID != 100 {
			t.Errorf("expected PID 4321/PPID 100, got %d/%d", ev.PID, ev.PPID)
		}
	default:
		t.Fatal("expected an event from a well-formed netlink datagram")
	}
}

func TestParseProcConnectorMsgs_MultipleMessages(t *testing.T) {
	ch := make(chan ProcessEvent, 2)
	c := &ESConsumer{events: ch}

	one := wrapNlMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 10, 1))
	two := wrapNlMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 20, 1))
	c.parseProcConnectorMsgs(append(one, two...))

	if len(ch) != 2 {
		t.Fatalf("expected 2 events from 2 messages, got %d", len(ch))
	}
	first, second := <-ch, <-ch
	if first.PID != 10 || second.PID != 20 {
		t.Errorf("expected PIDs 10 and 20, got %d and %d", first.PID, second.PID)
	}
}

func TestParseProcConnectorMsgs_MalformedLengthsAreSafe(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	c := &ESConsumer{events: ch}

	// nlmsg_len larger than the buffer
	bad := wrapNlMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 1, 1))
	binary.NativeEndian.PutUint32(bad[0:4], uint32(len(bad)+100))
	c.parseProcConnectorMsgs(bad)

	// nlmsg_len smaller than the header
	bad2 := wrapNlMsg(buildCnExitMsg(cnIdxProc, cnValProc, procEventExit, 1, 1))
	binary.NativeEndian.PutUint32(bad2[0:4], 4)
	c.parseProcConnectorMsgs(bad2)

	// zero-length
	c.parseProcConnectorMsgs(nil)

	if len(ch) != 0 {
		t.Error("malformed datagrams must not produce events")
	}
}

func TestProcInfoFromPID_Self(t *testing.T) {
	ppid, uid := procInfoFromPID(os.Getpid())
	if ppid != os.Getppid() {
		t.Errorf("expected PPID %d, got %d", os.Getppid(), ppid)
	}
	if int(uid) != os.Getuid() {
		t.Errorf("expected UID %d, got %d", os.Getuid(), uid)
	}
}

func TestProcInfoFromPID_NonexistentProcess(t *testing.T) {
	ppid, uid := procInfoFromPID(-1)
	if ppid != 0 || uid != 0 {
		t.Errorf("expected zero values for nonexistent pid, got ppid=%d uid=%d", ppid, uid)
	}
}

func TestFdReadlink(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "edr-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got := fdReadlink(int(f.Fd()))
	if got != f.Name() {
		t.Errorf("expected %q, got %q", f.Name(), got)
	}
}

func TestNewESConsumer_RequiresPrivilege(t *testing.T) {
	ch := make(chan ProcessEvent, 1)
	consumer, err := NewESConsumer(ch)
	if err != nil {
		// fanotify_init requires CAP_SYS_ADMIN; expected in unprivileged environments.
		t.Skipf("fanotify unavailable (unprivileged): %v", err)
	}
	if consumer.fanotifyFd <= 0 {
		t.Error("expected a valid fanotify fd")
	}
}
