package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

type Config struct {
	ServerCertFile string
	ServerKeyFile  string
	CACertFile     string
	ClientAuthType tls.ClientAuthType
}

// NewServerTLSConfig creates a TLS configuration for gRPC server with optional mTLS
func NewServerTLSConfig(cfg Config) (credentials.TransportCredentials, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	if cfg.CACertFile != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}

		tlsConfig.ClientCAs = certPool
		tlsConfig.ClientAuth = cfg.ClientAuthType

		if tlsConfig.ClientAuth == 0 {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return credentials.NewTLS(tlsConfig), nil
}

// NewClientTLSConfig creates a TLS configuration for gRPC client with optional mTLS
func NewClientTLSConfig(serverName, caCertFile, clientCertFile, clientKeyFile string) (credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		ServerName: serverName,
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}

	if clientCertFile != "" && clientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	return credentials.NewTLS(tlsConfig), nil
}

// DefaultServerConfig returns a production-ready server TLS config with mTLS
func DefaultServerConfig() Config {
	return Config{
		ServerCertFile: "certs/server.crt",
		ServerKeyFile:  "certs/server.key",
		CACertFile:     "certs/ca.crt",
		ClientAuthType: tls.RequireAndVerifyClientCert,
	}
}

// DevServerConfig returns a development server TLS config without client verification
func DevServerConfig() Config {
	return Config{
		ServerCertFile: "certs/server.crt",
		ServerKeyFile:  "certs/server.key",
		ClientAuthType: tls.NoClientCert,
	}
}
