package edr

/*
#cgo CFLAGS: -mmacosx-version-min=10.15
#cgo LDFLAGS: -mmacosx-version-min=10.15 -framework Foundation -lEndpointSecurity
#include "es_wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"time"
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
	} else if msg.event_type == C.ES_EVENT_TYPE_NOTIFY_EXIT {
		eventType = EventNotifyExit
	}

	globalConsumer.events <- ProcessEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		// We can parse the exact fields from msg->process using C struct accessors
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
