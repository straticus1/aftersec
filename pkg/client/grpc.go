package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	grpcapi "aftersec/pkg/api/grpc"
)

const clientTLSMinimumVersion = tls.VersionTLS13

// buildClientTLSConfig constructs a verified TLS 1.3 configuration.
// Threats: missing/untrusted roots, partial client identities, and certificate
// hostname bypasses are rejected; verification is never disabled.
func buildClientTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if cfg.CA == "" {
		return nil, fmt.Errorf("TLS CA bundle is required")
	}
	if (cfg.Cert == "") != (cfg.Key == "") {
		return nil, fmt.Errorf("TLS client certificate and key must be configured together")
	}
	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("TLS CA bundle contains no valid certificates")
	}
	tlsConfig := &tls.Config{
		MinVersion: clientTLSMinimumVersion,
		RootCAs:    roots,
		ServerName: cfg.ServerName,
	}
	if cfg.Cert != "" {
		identity, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("load TLS client identity: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{identity}
	}
	return tlsConfig, nil
}

// EnterpriseClient is a wrapper around the generated gRPC client
type EnterpriseClient struct {
	conn       *grpc.ClientConn
	grpcClient grpcapi.EnterpriseServiceClient
	config     *ClientConfig
}

// NewEnterpriseClient initializes a connection to the management server
func NewEnterpriseClient(cfg *ClientConfig) (*EnterpriseClient, error) {
	if cfg.Server.Address == "" {
		return nil, fmt.Errorf("management server address is not configured")
	}

	opts := []grpc.DialOption{}

	if cfg.Server.TLS.Cert != "" || cfg.Server.TLS.Key != "" || cfg.Server.TLS.CA != "" {
		tlsConfig, err := buildClientTLSConfig(cfg.Server.TLS)
		if err != nil {
			return nil, fmt.Errorf("configure management TLS: %w", err)
		}
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Add timeout for connection dialing
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.Server.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to management server: %v", err)
	}

	client := grpcapi.NewEnterpriseServiceClient(conn)

	return &EnterpriseClient{
		conn:       conn,
		grpcClient: client,
		config:     cfg,
	}, nil
}

// Close tears down the connection
func (c *EnterpriseClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Enroll issues a registration request using the host details
func (c *EnterpriseClient) Enroll(ctx context.Context, hwID, hostname, os string) (*grpcapi.EnrollResponse, error) {
	req := &grpcapi.EnrollRequest{
		HardwareId:   hwID,
		Hostname:     hostname,
		OsVersion:    os,
		AgentVersion: "1.0.0", // Hardcoded stub
	}
	return c.grpcClient.Enroll(ctx, req)
}

func (c *EnterpriseClient) EnrollAttested(ctx context.Context, provider EvidenceProvider, store CredentialStore, caPEM []byte, details EnrollmentDetails) (*grpcapi.EnrollResponse, error) {
	return RunAttestedEnrollment(ctx, c.grpcClient, provider, store, caPEM, details, time.Now())
}

// Heartbeat pushes telemetry to the management server
func (c *EnterpriseClient) Heartbeat(ctx context.Context, tenantID, hwID, status string) (*grpcapi.HeartbeatResponse, error) {
	req := &grpcapi.HeartbeatRequest{
		TenantId:   tenantID,
		HardwareId: hwID,
		Status:     status,
		Timestamp:  time.Now().Unix(),
	}
	return c.grpcClient.Heartbeat(ctx, req)
}

// StreamEvents opens a unidirectional high-throughput stream to the Orchestrator
func (c *EnterpriseClient) StreamEvents(ctx context.Context) (grpcapi.EnterpriseService_StreamEventsClient, error) {
	return c.grpcClient.StreamEvents(ctx)
}

// ConnectCommandStream initiates the persistent bi-directional MDM queue
func (c *EnterpriseClient) ConnectCommandStream(ctx context.Context) (grpcapi.EnterpriseService_ConnectCommandStreamClient, error) {
	return c.grpcClient.ConnectCommandStream(ctx)
}

// StreamTelemetryBatch takes local SQLite events and streams them over gRPC, returning the processed count
func (c *EnterpriseClient) StreamTelemetryBatch(ctx context.Context, tenantID, hwID string, events []map[string]any) (int32, error) {
	stream, err := c.grpcClient.StreamEvents(ctx)
	if err != nil {
		return 0, err
	}

	for _, ev := range events {
		var unixTime int64
		// Dynamic typing helper to handle SQL timestamp parsing
		if ts, ok := ev["timestamp"].(time.Time); ok {
			unixTime = ts.Unix()
		}

		eventType, _ := ev["event_type"].(string)
		detailsRaw, _ := ev["details"].(string)

		clientEv := &grpcapi.ClientEvent{
			TenantId:   tenantID,
			HardwareId: hwID,
			Timestamp:  unixTime,
			EventType:  eventType,
			Payload:    detailsRaw,
		}

		if err := stream.Send(clientEv); err != nil {
			return 0, err
		}
	}

	ack, err := stream.CloseAndRecv()
	if err != nil {
		return 0, err
	}
	return ack.EventsProcessed, nil
}
