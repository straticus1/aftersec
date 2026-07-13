package client

import (
	"context"
	"errors"
	"io"
	"testing"

	grpcapi "aftersec/pkg/api/grpc"
)

type fakeCommandStream struct {
	commands []*grpcapi.ServerCommand
	sent     []*grpcapi.CommandResult
}

func (s *fakeCommandStream) Recv() (*grpcapi.ServerCommand, error) {
	if len(s.commands) == 0 {
		return nil, io.EOF
	}
	command := s.commands[0]
	s.commands = s.commands[1:]
	return command, nil
}
func (s *fakeCommandStream) Send(result *grpcapi.CommandResult) error {
	s.sent = append(s.sent, result)
	return nil
}

type fakeCommandExecutor struct {
	output []byte
	err    error
	calls  int
}

func (f *fakeCommandExecutor) Execute(context.Context, string, map[string]string) ([]byte, error) {
	f.calls++
	return f.output, f.err
}

func TestCommandProcessorRejectsMalformedCommandWithoutExecution(t *testing.T) {
	e := &fakeCommandExecutor{}
	p := NewCommandProcessor("tenant", "endpoint", e, 1024)
	r := p.Process(context.Background(), &grpcapi.ServerCommand{CommandId: "", Payload: "token"})
	if r.Status != "FAILED" || e.calls != 0 {
		t.Fatalf("result=%+v calls=%d", r, e.calls)
	}
}

func TestCommandProcessorReturnsBoundedFailure(t *testing.T) {
	e := &fakeCommandExecutor{err: errors.New("secret internal detail")}
	p := NewCommandProcessor("tenant", "endpoint", e, 16)
	r := p.Process(context.Background(), &grpcapi.ServerCommand{CommandId: "one", Action: "REMOTE_ACTION", Payload: "token"})
	if r.Status != "FAILED" || r.Output != "command rejected" {
		t.Fatalf("result=%+v", r)
	}
}

func TestCommandProcessorExecutesSignedPayload(t *testing.T) {
	e := &fakeCommandExecutor{output: []byte("done")}
	p := NewCommandProcessor("tenant", "endpoint", e, 16)
	r := p.Process(context.Background(), &grpcapi.ServerCommand{CommandId: "one", Action: "REMOTE_ACTION", Payload: "token"})
	if r.Status != "SUCCESS" || r.Output != "done" || r.TenantId != "tenant" || r.HardwareId != "endpoint" {
		t.Fatalf("result=%+v", r)
	}
}

func TestRunCommandLoopRegistersAndReportsEveryCommand(t *testing.T) {
	e := &fakeCommandExecutor{output: []byte("done")}
	p := NewCommandProcessor("tenant", "endpoint", e, 16)
	stream := &fakeCommandStream{commands: []*grpcapi.ServerCommand{{CommandId: "one", Action: "REMOTE_ACTION", Payload: "token"}}}
	if err := RunCommandLoop(context.Background(), stream, p); !errors.Is(err, io.EOF) {
		t.Fatalf("err=%v", err)
	}
	if len(stream.sent) != 2 || stream.sent[0].Status != "ACK" || stream.sent[1].Status != "SUCCESS" {
		t.Fatalf("sent=%+v", stream.sent)
	}
}
