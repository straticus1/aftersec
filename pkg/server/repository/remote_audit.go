package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"aftersec/pkg/response"
)

type RemoteResponseAuditRepository struct {
	db *sql.DB
}

func NewRemoteResponseAuditRepository(db *sql.DB) *RemoteResponseAuditRepository {
	return &RemoteResponseAuditRepository{db: db}
}

type persistentAuditPayload struct {
	OrganizationID string          `json:"organization_id"`
	EndpointID     string          `json:"endpoint_id"`
	CommandID      string          `json:"command_id"`
	Action         response.Action `json:"action"`
	Status         string          `json:"status"`
	ActorID        string          `json:"actor_id"`
	CreatedAt      time.Time       `json:"created_at"`
}

// AppendDispatch writes an authorized lifecycle record before transport
// dispatch. Threats: tenant crossover, chain races, and audit-write failures
// cannot produce an unaudited command.
func (r *RemoteResponseAuditRepository) AppendDispatch(ctx context.Context, event response.AuditEvent, actorID string) error {
	if event.TenantID == "" || event.EndpointID == "" || event.CommandID == "" ||
		event.Action == "" || event.Status == "" || event.Timestamp.IsZero() || actorID == "" {
		return fmt.Errorf("complete remote response audit event is required")
	}
	return r.append(ctx, persistentAuditPayload{
		OrganizationID: event.TenantID,
		EndpointID:     event.EndpointID,
		CommandID:      event.CommandID,
		Action:         event.Action,
		Status:         event.Status,
		ActorID:        actorID,
		CreatedAt:      event.Timestamp.UTC(),
	})
}

// AppendResult resolves immutable action/actor metadata from the authorization
// record and appends the endpoint result to the same tenant hash chain.
func (r *RemoteResponseAuditRepository) AppendResult(ctx context.Context, tenantID, endpointID, commandID, status string, at time.Time) error {
	if tenantID == "" || endpointID == "" || commandID == "" ||
		(status != "SUCCESS" && status != "FAILED") || at.IsZero() {
		return fmt.Errorf("valid remote response result is required")
	}
	if r == nil || r.db == nil {
		return fmt.Errorf("remote response audit database is unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = setAuditTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	var action response.Action
	var actorID string
	err = tx.QueryRowContext(ctx, `
		SELECT action, actor_id
		FROM remote_response_audit
		WHERE organization_id = $1 AND endpoint_id = $2 AND command_id = $3
		  AND status = 'DISPATCH_REQUESTED'
		ORDER BY id DESC LIMIT 1`,
		tenantID, endpointID, commandID).Scan(&action, &actorID)
	if err != nil {
		return fmt.Errorf("resolve authorized remote action: %w", err)
	}
	if err = appendAuditTx(ctx, tx, persistentAuditPayload{
		OrganizationID: tenantID,
		EndpointID:     endpointID,
		CommandID:      commandID,
		Action:         action,
		Status:         status,
		ActorID:        actorID,
		CreatedAt:      at.UTC(),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *RemoteResponseAuditRepository) append(ctx context.Context, payload persistentAuditPayload) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("remote response audit database is unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = setAuditTenant(ctx, tx, payload.OrganizationID); err != nil {
		return err
	}
	if err = appendAuditTx(ctx, tx, payload); err != nil {
		return err
	}
	return tx.Commit()
}

func setAuditTenant(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aftersec.organization_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("set remote audit tenant: %w", err)
	}
	// Serialize each tenant chain without blocking unrelated organizations.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID); err != nil {
		return fmt.Errorf("lock remote audit chain: %w", err)
	}
	return nil
}

func appendAuditTx(ctx context.Context, tx *sql.Tx, payload persistentAuditPayload) error {
	var previous [sha256.Size]byte
	var stored []byte
	err := tx.QueryRowContext(ctx, `
		SELECT record_hash FROM remote_response_audit
		WHERE organization_id = $1 ORDER BY id DESC LIMIT 1`,
		payload.OrganizationID).Scan(&stored)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read remote audit head: %w", err)
	}
	if err == nil {
		if len(stored) != sha256.Size {
			return fmt.Errorf("remote audit head is corrupt")
		}
		copy(previous[:], stored)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode remote audit payload: %w", err)
	}
	hash := sha256.New()
	hash.Write(previous[:])
	hash.Write(body)
	recordHash := hash.Sum(nil)
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO remote_response_audit
			(organization_id, endpoint_id, command_id, action, status, actor_id,
			 previous_hash, record_hash, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		payload.OrganizationID, payload.EndpointID, payload.CommandID,
		payload.Action, payload.Status, payload.ActorID,
		previous[:], recordHash, payload.CreatedAt); err != nil {
		return fmt.Errorf("append remote audit record: %w", err)
	}
	return nil
}
