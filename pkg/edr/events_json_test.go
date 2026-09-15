package edr

import (
	"encoding/json"
	"testing"
	"unsafe"
)

func TestProcessEventJSONExcludesNativeMessage(t *testing.T) {
	marker := 1
	b, err := json.Marshal(ProcessEvent{Type: EventNotifyExec, PID: 42, ExecPath: "/usr/bin/example", Msg: unsafe.Pointer(&marker)})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(b, &value); err != nil {
		t.Fatal(err)
	}
	if value["pid"] != float64(42) || value["exec_path"] != "/usr/bin/example" {
		t.Fatal(string(b))
	}
	if _, exists := value["Msg"]; exists {
		t.Fatal("native pointer serialized")
	}
}
