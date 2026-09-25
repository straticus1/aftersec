package edr

import (
	"time"
	"unsafe"
)

// EventType represents the type of Endpoint Security event
type EventType string

const (
	EventNotifyExec   EventType = "notify_exec"
	EventAuthExec     EventType = "auth_exec"
	EventNotifyCreate EventType = "notify_create"
	EventNotifyExit   EventType = "notify_exit"
	EventNotifyMount  EventType = "notify_mount"
	EventNotifyWrite  EventType = "notify_write"
	EventAuthWrite    EventType = "auth_write"
	EventNotifyOpen   EventType = "notify_open"
	EventNotifyClose  EventType = "notify_close"
	EventNotifyRename EventType = "notify_rename"
	EventNotifyUnlink EventType = "notify_unlink"
	EventNotifyTCC    EventType = "notify_tcc"
)

// ProcessEvent holds normalized telemetry for a process/filesystem event
type ProcessEvent struct {
	Type          EventType
	Timestamp     time.Time
	PID           int
	PPID          int
	ExecPath      string
	ActorPath     string
	MountPath     string
	DestPath      string
	TCCService    string
	TCCIdentity   string
	Args          []string `json:"-"`
	ArgsTruncated bool     `json:"-"`
	UID           uint32
	Msg           unsafe.Pointer // Native es_message_t pointer for auth responses
}
