//go:build darwin

package display

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var out error
	err = raw.Control(func(fd uintptr) {
		cred, credErr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			out = credErr
			return
		}
		uid = int(cred.Uid)
	})
	if err != nil {
		return -1, err
	}
	if out != nil {
		return -1, fmt.Errorf("display peer credentials: %w", out)
	}
	return uid, nil
}
