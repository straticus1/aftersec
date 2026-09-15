package edr

import "encoding/json"

// MarshalJSON excludes the native authorization message pointer. The pointer is
// process-local and encoding/json cannot serialize unsafe.Pointer, even when nil.
func (e ProcessEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"type": e.Type, "timestamp": e.Timestamp, "pid": e.PID, "ppid": e.PPID,
		"exec_path": e.ExecPath, "actor_path": e.ActorPath, "mount_path": e.MountPath,
		"args": e.Args, "uid": e.UID,
	})
}
