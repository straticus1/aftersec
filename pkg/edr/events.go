package edr

import "time"

// EventType represents the type of Endpoint Security event
type EventType string

const (
	EventNotifyExec   EventType = "notify_exec"
	EventNotifyCreate EventType = "notify_create"
	EventNotifyExit   EventType = "notify_exit"
)

// ProcessEvent holds normalized telemetry for a process/filesystem event
type ProcessEvent struct {
	Type      EventType
	Timestamp time.Time
	PID       int
	PPID      int
	ExecPath  string
	Args      []string
	UID       uint32
}
