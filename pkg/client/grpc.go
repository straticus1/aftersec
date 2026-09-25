package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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
	if cfg == nil || cfg.Server == nil || cfg.Server.Address == "" {
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
		return nil, fmt.Errorf("management TLS CA is required; cleartext enrollment is disabled")
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

// SendStolenCamera uploads one camera frame. The server stores it only when
// this endpoint is marked stolen, and the returned payload never includes the
// picture. True means the server kept the frame.
func (c *EnterpriseClient) SendStolenCamera(ctx context.Context, tenantID, hwID, payload string) (bool, error) {
	stream, err := c.StreamEvents(ctx)
	if err != nil {
		return false, err
	}
	if err = stream.Send(&grpcapi.ClientEvent{
		TenantId: tenantID, HardwareId: hwID, Timestamp: time.Now().Unix(),
		EventType: "stolen_camera", Payload: payload,
	}); err != nil {
		return false, err
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return false, err
	}
	return ack.GetMessage() == "stolen camera stored" && ack.GetEventsProcessed() > 0, nil
}

// SendPreserve uploads one evidence archive. The server stores it only when
// this endpoint is marked for that incident, and the journal keeps the stamp
// rather than the archive. True means the server kept the archive.
func (c *EnterpriseClient) SendPreserve(ctx context.Context, tenantID, hwID, payload string) (bool, error) {
	stream, err := c.StreamEvents(ctx)
	if err != nil {
		return false, err
	}
	if err = stream.Send(&grpcapi.ClientEvent{
		TenantId: tenantID, HardwareId: hwID, Timestamp: time.Now().Unix(),
		EventType: "preserve_bundle", Payload: payload,
	}); err != nil {
		return false, err
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return false, err
	}
	return ack.GetMessage() == "preserve stored" && ack.GetEventsProcessed() > 0, nil
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
		unixTime, err := TelemetryUnix(ev["timestamp"])
		if err != nil {
			return 0, fmt.Errorf("telemetry timestamp: %w", err)
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

// NewManagementHTTPClient uses the same verified identity and roots as gRPC.
func NewManagementHTTPClient(cfg TLSConfig) (*http.Client, error) {
	tlsConfig, err := buildClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport, Timeout: 45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
