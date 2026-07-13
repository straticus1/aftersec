package client

import (
	"context"
	"fmt"

	grpcapi "aftersec/pkg/api/grpc"
)

type RemoteCommandExecutor interface {
	Execute(context.Context, string, map[string]string) ([]byte, error)
}

type CommandStream interface {
	Send(*grpcapi.CommandResult) error
	Recv() (*grpcapi.ServerCommand, error)
}

type CommandProcessor struct {
	tenantID, endpointID string
	executor             RemoteCommandExecutor
	maxOutput            int
}

func NewCommandProcessor(tenantID, endpointID string, e RemoteCommandExecutor, maxOutput int) *CommandProcessor {
	return &CommandProcessor{tenantID: tenantID, endpointID: endpointID, executor: e, maxOutput: maxOutput}
}

// Process accepts only signed REMOTE_ACTION payloads and returns bounded,
// non-sensitive results. Threats: arbitrary legacy command strings and raw
// executor errors are never executed or reflected to the server.
func (p *CommandProcessor) Process(ctx context.Context, cmd *grpcapi.ServerCommand) *grpcapi.CommandResult {
	result := &grpcapi.CommandResult{TenantId: p.tenantID, HardwareId: p.endpointID, Status: "FAILED", Output: "command rejected"}
	if cmd == nil {
		return result
	}
	result.CommandId = cmd.CommandId
	if p.tenantID == "" || p.endpointID == "" || p.executor == nil || p.maxOutput <= 0 || cmd.CommandId == "" || len(cmd.CommandId) > 128 || cmd.Action != "REMOTE_ACTION" || cmd.Payload == "" || len(cmd.Payload) > 16*1024 {
		return result
	}
	out, err := p.executor.Execute(ctx, cmd.Payload, nil)
	if err != nil {
		return result
	}
	if len(out) > p.maxOutput {
		return result
	}
	result.Status = "SUCCESS"
	result.Output = string(out)
	return result
}

func (p *CommandProcessor) Registration() *grpcapi.CommandResult {
	return &grpcapi.CommandResult{TenantId: p.tenantID, HardwareId: p.endpointID, Status: "ACK", Output: fmt.Sprintf("command processor ready")}
}

// RunCommandLoop registers endpoint identity before receiving commands and
// reports one bounded result per received command. Stream failures are surfaced
// so the daemon can reconnect rather than silently losing control messages.
func RunCommandLoop(ctx context.Context, stream CommandStream, processor *CommandProcessor) error {
	if stream == nil || processor == nil {
		return fmt.Errorf("command stream and processor are required")
	}
	if err := stream.Send(processor.Registration()); err != nil {
		return fmt.Errorf("register command stream: %w", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		command, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(processor.Process(ctx, command)); err != nil {
			return fmt.Errorf("report command result: %w", err)
		}
	}
}
