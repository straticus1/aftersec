package compliance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestControlHelper(t *testing.T) {
	if os.Getenv("AFTERSEC_CONTROL_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "fail":
		fmt.Print("insecure")
		os.Exit(1)
	case "large":
		fmt.Print(strings.Repeat("x", 1000))
		os.Exit(0)
	case "wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	default:
		fmt.Print("secure")
		os.Exit(0)
	}
}
func TestCommandExecutorExitAndLimits(t *testing.T) {
	t.Setenv("AFTERSEC_CONTROL_HELPER", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode    string
		passed  bool
		wantErr error
	}{
		{"pass", true, nil}, {"fail", false, nil}, {"large", false, ErrOutputTooLarge}, {"wait", false, context.DeadlineExceeded},
	} {
		r := Runner{Executor: CommandExecutor{}, Timeout: 2 * time.Second, MaxOutputBytes: 20}
		if tc.mode == "wait" {
			r.Timeout = 20 * time.Millisecond
		}
		result, err := r.Run(context.Background(), Control{ID: "test", Command: []string{exe, "-test.run=^TestControlHelper$", "--", tc.mode}})
		if !errors.Is(err, tc.wantErr) || result.Passed != tc.passed {
			t.Errorf("%s: %+v %v", tc.mode, result, err)
		}
	}
}
