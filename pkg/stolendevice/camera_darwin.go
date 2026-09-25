//go:build darwin

package stolendevice

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework AVFoundation -framework CoreMedia
#include <stdint.h>
#include <stdlib.h>
int aftersec_camera_jpeg(uint8_t **out, int *out_len);
*/
import "C"
import (
	"context"
	"fmt"
	"unsafe"
)

// CaptureCamera takes one JPEG from the default camera. A missing permission
// or a missing camera is an error. The system indicator is left alone.
func CaptureCamera(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out *C.uint8_t
	var n C.int
	rc := C.aftersec_camera_jpeg(&out, &n)
	if out != nil {
		defer C.free(unsafe.Pointer(out))
	}
	switch rc {
	case 0:
		if n <= 0 || out == nil {
			return nil, fmt.Errorf("camera capture failed")
		}
		return C.GoBytes(unsafe.Pointer(out), n), nil
	case 3:
		return nil, fmt.Errorf("camera permission is not granted")
	default:
		return nil, fmt.Errorf("camera capture failed")
	}
}
