//go:build darwin

package stolendevice

/*
#include <notify.h>
#include <stdint.h>
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"fmt"
	"sync"
	"unsafe"
)

var (
	lockOnce  sync.Once
	lockToken C.int
	lockErr   error
)

// SessionUnlocked reports whether the console session is unlocked.
// A failure to read the lock state is an error, not a guess that it is open.
func SessionUnlocked(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	lockOnce.Do(func() {
		name := C.CString("com.apple.screenIsLocked")
		defer C.free(unsafe.Pointer(name))
		if C.notify_register_check(name, &lockToken) != 0 {
			lockErr = fmt.Errorf("lock state is unavailable")
		}
	})
	if lockErr != nil {
		return false, lockErr
	}
	var state C.uint64_t
	if C.notify_get_state(lockToken, &state) != 0 {
		return false, fmt.Errorf("lock state is unavailable")
	}
	return state == 0, nil
}
