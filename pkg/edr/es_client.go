//go:build darwin

package edr

/*
#cgo CFLAGS: -mmacosx-version-min=11.0
#cgo LDFLAGS: -mmacosx-version-min=11.0 -framework Foundation -lEndpointSecurity -lbsm
#include "es_wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// ESConsumer manages the Endpoint Security API subscription
type ESConsumer struct {
	client *C.es_client_t
	events chan<- ProcessEvent
}

func NotifyWriteEventCode() uint32  { return uint32(C.ES_EVENT_TYPE_NOTIFY_WRITE) }
func AuthWriteEventCode() uint32    { return uint32(C.auth_open_event_code()) }
func NotifyRenameEventCode() uint32 { return uint32(C.notify_rename_event_code()) }

// globalConsumer is required because CGO callbacks cannot carry Go context cleanly
var globalConsumer *ESConsumer

//export esEventCallback_cgo
func esEventCallback_cgo(client *C.es_client_t, msg *C.es_message_t) {
	if globalConsumer == nil {
		return
	}

	// This is a simplified event handler.
	// In a full implementation, we'd cast msg.event and parse es_event_exec_t, etc.
	// For now, we emit basic raw events to prove the architecture.
	eventType := EventNotifyCreate
	if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_EXEC {
		eventType = EventNotifyExec
	} else if msg.event_type == C.ES_EVENT_TYPE_AUTH_EXEC { // NEW: Interception
		eventType = EventAuthExec
		// retain the message because we will respond asynchronously
		C.retain_message_safe(msg)
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_EXIT {
		eventType = EventNotifyExit
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_MOUNT { // DMG/ISO Interception
		eventType = EventNotifyMount
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_WRITE {
		eventType = EventNotifyWrite
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_RENAME {
		eventType = EventNotifyRename
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_UNLINK {
		eventType = EventNotifyUnlink
	} else if msg.event_type == C.ES_EVENT_TYPE_AUTH_OPEN && bool(C.open_requests_write(msg)) {
		eventType = EventAuthWrite
		C.retain_message_safe(msg)
	} else if msg.event_type == C.ES_EVENT_TYPE_AUTH_OPEN {
		// AUTH_OPEN is subscribed only to intercept mutations. Reads are
		// immediately allowed and never cross the asynchronous Go boundary.
		C.retain_message_safe(msg)
		C.respond_auth_and_release(client, msg, true, false)
		return
	}

	var execPath string
	var actorPath string
	var mountPath string
	var destPath string
	var tccService string
	var tccIdentity string
	var args []string
	var argsTruncated bool

	pid := int(C.get_pid(msg))
	ppid := int(C.get_ppid(msg))
	uid := uint32(C.get_uid(msg))

	var length C.int
	cPath := C.get_executable_path(msg, &length)
	if length > 0 {
		actorPath = C.GoStringN(cPath, length)
		execPath = actorPath
	}
	if eventType == EventNotifyExec || eventType == EventAuthExec {
		var targetLen C.int
		target := C.get_exec_target_path(msg, &targetLen)
		if targetLen > 0 {
			execPath = C.GoStringN(target, targetLen)
		}
		args, argsTruncated = copyExecArgs(msg)
	}
	var service [256]C.char
	var identity [1024]C.char
	if C.copy_tcc_revocation(msg, &service[0], 256, &identity[0], 1024) == 1 {
		eventType = EventNotifyTCC
		tccService = C.GoString(&service[0])
		tccIdentity = C.GoString(&identity[0])
	}

	// Mount path extraction (only populated if struct contains statfs struct pointer)
	var mLen C.int
	mPath := C.get_mount_path(msg, &mLen)
	if mLen > 0 {
		mountPath = C.GoStringN(mPath, mLen)
	}
	if eventType == EventNotifyWrite {
		var tLen C.int
		tPath := C.get_target_path(msg, &tLen)
		if tLen > 0 {
			execPath = C.GoStringN(tPath, tLen)
		}
	}
	if eventType == EventNotifyRename {
		var tLen C.int
		tPath := C.get_rename_path(msg, &tLen)
		if tLen > 0 {
			execPath = C.GoStringN(tPath, tLen)
		}
		var existingLen C.int
		existing := C.get_rename_existing_dest(msg, &existingLen)
		var dirLen C.int
		dir := C.get_rename_new_dir(msg, &dirLen)
		var nameLen C.int
		name := C.get_rename_new_name(msg, &nameLen)
		existingPath, dirPath, namePath := "", "", ""
		if existingLen > 0 {
			existingPath = C.GoStringN(existing, existingLen)
		}
		if dirLen > 0 {
			dirPath = C.GoStringN(dir, dirLen)
		}
		if nameLen > 0 {
			namePath = C.GoStringN(name, nameLen)
		}
		destPath = JoinRenameDest(existingPath, dirPath, namePath)
	}
	if eventType == EventNotifyUnlink {
		var tLen C.int
		tPath := C.get_unlink_path(msg, &tLen)
		if tLen > 0 {
			execPath = C.GoStringN(tPath, tLen)
		}
	}
	if eventType == EventAuthWrite {
		var tLen C.int
		tPath := C.get_open_target_path(msg, &tLen)
		if tLen > 0 {
			execPath = C.GoStringN(tPath, tLen)
		}
	}

	globalConsumer.events <- ProcessEvent{
		Type:          eventType,
		Timestamp:     time.Now(),
		PID:           pid,
		PPID:          ppid,
		ExecPath:      execPath,
		ActorPath:     actorPath,
		MountPath:     mountPath,
		DestPath:      destPath,
		TCCService:    tccService,
		TCCIdentity:   tccIdentity,
		Args:          args,
		ArgsTruncated: argsTruncated,
		UID:           uid,
		Msg:           unsafe.Pointer(msg),
	}
}

func copyExecArgs(msg *C.es_message_t) ([]string, bool) {
	count := int(C.exec_arg_count(msg))
	if count <= 0 {
		return nil, false
	}
	truncated := count > 64
	if truncated {
		count = 64
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		var length C.int
		raw := C.exec_arg(msg, C.int(i), &length)
		if length <= 0 {
			continue
		}
		if length > 4096 {
			return args, true
		}
		args = append(args, C.GoStringN(raw, length))
	}
	return args, truncated
}

func AuthExecEventCode() uint32    { return uint32(C.auth_exec_event_code()) }
func NotifyExecEventCode() uint32  { return uint32(C.notify_exec_event_code()) }
func NotifyExitEventCode() uint32  { return uint32(C.notify_exit_event_code()) }
func NotifyMountEventCode() uint32 { return uint32(C.notify_mount_event_code()) }
func NotifyUnlinkEventCode() uint32 {
	return uint32(C.notify_unlink_event_code())
}
func NotifyTCCEventCode() uint32 { return uint32(C.notify_tcc_event_code()) }

// NewESConsumer allocates and initializes a new Apple Endpoint Security client.
// WARNING: This requires the `com.apple.developer.endpoint-security.client` entitlement.
func NewESConsumer(eventChannel chan<- ProcessEvent) (*ESConsumer, error) {
	consumer := &ESConsumer{
		events: eventChannel,
	}

	var client *C.es_client_t

	// We initialize the ES client via our Objective-C wrapper
	res := C.create_es_client(&client)
	if res != C.ES_NEW_CLIENT_RESULT_SUCCESS {
		return nil, fmt.Errorf("failed to create Endpoint Security client. Ensure process is entitled and running as root. Error code: %d", res)
	}

	consumer.client = client
	globalConsumer = consumer

	return consumer, nil
}

// Subscribe configures the ES client to listen for specific global system events.
func (c *ESConsumer) Subscribe(events []uint32) error {
	if c.client == nil {
		return errors.New("es client not initialized")
	}

	if len(events) == 0 {
		return nil
	}

	// Convert Go uint32 slice to C.es_event_type_t array
	cEvents := make([]C.es_event_type_t, len(events))
	for i, e := range events {
		cEvents[i] = C.es_event_type_t(e)
	}

	res := C.es_subscribe(c.client, &cEvents[0], C.uint32_t(len(cEvents)))
	if res != C.ES_RETURN_SUCCESS {
		return fmt.Errorf("failed to subscribe to ES events: %d", res)
	}

	return nil
}

// RespondAuth allows or denies an intercepted AUTH event and cleans up the message.
func (c *ESConsumer) RespondAuth(event ProcessEvent, allow bool, cache bool) error {
	if c.client == nil {
		return errors.New("es client not initialized")
	}
	if event.Msg == nil {
		return errors.New("event message pointer is nil, cannot respond")
	}

	cAllow := C.bool(allow)
	cCache := C.bool(cache)
	cMsg := (*C.es_message_t)(event.Msg)

	C.respond_auth_and_release(c.client, cMsg, cAllow, cCache)
	return nil
}
