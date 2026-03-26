package edr

/*
#cgo CFLAGS: -mmacosx-version-min=10.15
#cgo LDFLAGS: -mmacosx-version-min=10.15 -framework Foundation -lEndpointSecurity -lbsm
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
		C.es_retain_message(msg)
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_EXIT {
		eventType = EventNotifyExit
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_MOUNT { // DMG/ISO Interception
		eventType = EventNotifyMount
	}

	var execPath string
	var mountPath string

	pid := int(C.get_pid(msg))
	ppid := int(C.get_ppid(msg))
	uid := uint32(C.get_uid(msg))
	
	var length C.int
	cPath := C.get_executable_path(msg, &length)
	if length > 0 {
		execPath = C.GoStringN(cPath, length)
	}

	// Mount path extraction (only populated if struct contains statfs struct pointer)
	var mLen C.int
	mPath := C.get_mount_path(msg, &mLen)
	if mLen > 0 {
		mountPath = C.GoStringN(mPath, mLen)
	}

	globalConsumer.events <- ProcessEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		PID:       pid,
		PPID:      ppid,
		ExecPath:  execPath,
		MountPath: mountPath,
		UID:       uid,
		Msg:       unsafe.Pointer(msg),
	}
}

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
