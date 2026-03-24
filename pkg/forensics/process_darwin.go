package forensics

/*
#include <libproc.h>
#include <stdlib.h>
#include <sys/socket.h>

int count_network_sockets(int pid) {
    int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bufsize <= 0) return 0;
    
    struct proc_fdinfo *fdinfo = malloc((size_t)bufsize);
    if (!fdinfo) return 0;
    
    bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo, bufsize);
    if (bufsize <= 0) {
        free(fdinfo);
        return 0;
    }
    
    int num_fds = bufsize / sizeof(struct proc_fdinfo);
    int net_count = 0;
    
    for (int i = 0; i < num_fds; i++) {
        if (fdinfo[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
            net_count++;
        }
    }
    
    free(fdinfo);
    return net_count;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// GetProcessPath securely retrieves the definitive executable path for a PID directly from the kernel.
func GetProcessPath(pid int) (string, error) {
	bufSize := C.PROC_PIDPATHINFO_MAXSIZE
	buf := (*C.char)(C.malloc(C.size_t(bufSize)))
	defer C.free(unsafe.Pointer(buf))

	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(buf), C.uint32_t(bufSize))
	if ret <= 0 {
		return "", fmt.Errorf("failed to get pid path for %d", pid)
	}

	return C.GoString(buf), nil
}

// GetOpenConnections returns the number of active network sockets (PROX_NETWORK fdtype) held by a PID.
func GetOpenConnections(pid int) (int, error) {
	count := C.count_network_sockets(C.int(pid))
	return int(count), nil
}
