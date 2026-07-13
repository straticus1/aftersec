package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

type EnrollmentCommit struct {
	HardwareID             string
	Hostname               string
	Platform               string
	AttestationFingerprint [sha256.Size]byte
	RefreshTokenHash       [sha256.Size]byte
	ClientCertificate      []byte
}

// PostgresCodeStore atomically consumes enrollment codes. Threats: concurrent,
// expired, replayed, and wrong-organization uses fail closed through one guarded
// UPDATE. Only code digests are persisted; raw codes never reach PostgreSQL.
type PostgresCodeStore struct {
	db *sql.DB
}

func NewPostgresCodeStore(db *sql.DB) *PostgresCodeStore { return &PostgresCodeStore{db: db} }

func (s *PostgresCodeStore) Put(ctx context.Context, organizationID string, digest [sha256.Size]byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO enrollment_codes (organization_id, code_hash, expires_at) VALUES ($1, $2, $3)",
		organizationID, digest[:], expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert enrollment code: %w", err)
	}
	return nil
}

func (s *PostgresCodeStore) Consume(ctx context.Context, organizationID string, digest [sha256.Size]byte, now time.Time) error {
	var id string
	err := s.db.QueryRowContext(ctx, `UPDATE enrollment_codes
		SET used_at = $3
		WHERE organization_id = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING id`, organizationID, digest[:], now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCodeInvalid
	}
	if err != nil {
		return fmt.Errorf("consume enrollment code: %w", err)
	}
	return nil
}

func (s *PostgresCodeStore) Finalize(ctx context.Context, organizationID string, digest [sha256.Size]byte, now time.Time, commit EnrollmentCommit) error {
	block, _ := pem.Decode(commit.ClientCertificate)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("decode issued client certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued client certificate: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment transaction: %w", err)
	}
	defer tx.Rollback()
	var codeID string
	err = tx.QueryRowContext(ctx, `UPDATE enrollment_codes
		SET used_at = $3
		WHERE organization_id = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING id`, organizationID, digest[:], now).Scan(&codeID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCodeInvalid
	}
	if err != nil {
		return fmt.Errorf("consume enrollment code: %w", err)
	}
	var endpointID string
	err = tx.QueryRowContext(ctx, `INSERT INTO endpoints
		(organization_id, hardware_id, hostname, platform, enrollment_status, enrollment_token_hash, client_certificate)
		VALUES ($1, $2, $3, $4, 'active', $5, $6)
		RETURNING id`, organizationID, commit.HardwareID, commit.Hostname, commit.Platform,
		commit.RefreshTokenHash[:], string(commit.ClientCertificate)).Scan(&endpointID)
	if err != nil {
		return fmt.Errorf("register attested endpoint: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO enrollment_audit
		(organization_id, hardware_id, platform, attestation_fingerprint, refresh_token_hash, certificate_serial, certificate_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, organizationID, commit.HardwareID, commit.Platform,
		commit.AttestationFingerprint[:], commit.RefreshTokenHash[:], certificate.SerialNumber.String(), certificate.NotAfter)
	if err != nil {
		return fmt.Errorf("append enrollment audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment transaction: %w", err)
	}
	return nil
}
