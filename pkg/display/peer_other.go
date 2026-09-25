//go:build !darwin && !linux

package display

import (
	"fmt"
	"net"
)

func peerUID(*net.UnixConn) (int, error) {
	return -1, fmt.Errorf("display peer credentials are not supported on this OS")
}
