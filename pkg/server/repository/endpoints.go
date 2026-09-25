package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const InventoryStatus = "inventory"

const endpointColumns = `id, organization_id, hostname, platform, enrollment_status, COALESCE(platform_version, ''), last_seen_at, metadata`

// ErrInventoryCode means the organization-scoped code is missing, expired, or already used.
var ErrInventoryCode = errors.New("inventory code is invalid")

type Endpoint struct {
	ID               string          `json:"id"`
	OrganizationID   string          `json:"organization_id"`
	Hostname         string          `json:"hostname"`
	Platform         string          `json:"platform"`
	EnrollmentStatus string          `json:"enrollment_status"`
	PlatformVersion  string          `json:"platform_version,omitempty"`
	LastSeenAt       *time.Time      `json:"last_seen_at,omitempty"`
	Posture          json.RawMessage `json:"posture,omitempty"`
}

// InventoryInput is one Windows reporter observation.
//
// Threats: the code is stored only as a digest and consumed once. The row is
// inventory, with no hardware id, refresh token, or client certificate. The
// posture bytes are the caller's already-bounded JSON.
type InventoryInput struct {
	OrganizationID string
	CodeDigest     [32]byte
	Hostname       string
	OSVersion      string
	ObservedAt     time.Time
	Posture        []byte
}

type EndpointRepository struct {
	db *sql.DB
}

func NewEndpointRepository(db *sql.DB) *EndpointRepository {
	return &EndpointRepository{db: db}
}

// Register maps an Endpoint memory object to Postgres persistence
func (r *EndpointRepository) Register(ctx context.Context, ep *Endpoint) error {
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO endpoints (organization_id, hostname, platform, enrollment_status)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		ep.OrganizationID, ep.Hostname, ep.Platform, ep.EnrollmentStatus).Scan(&ep.ID)
	return err
}

// GetByHostname returns a persisted endpoint by hostname signature
func (r *EndpointRepository) GetByHostname(ctx context.Context, hostname string) (*Endpoint, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+endpointColumns+" FROM endpoints WHERE hostname = $1 LIMIT 1", hostname)
	ep, err := scanEndpoint(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ep, nil
}

// List returns all endpoints with optional organization filter
func (r *EndpointRepository) List(ctx context.Context, orgID string) ([]*Endpoint, error) {
	var query string
	var args []interface{}

	if orgID != "" {
		query = "SELECT " + endpointColumns + " FROM endpoints WHERE organization_id = $1 ORDER BY created_at DESC"
		args = append(args, orgID)
	} else {
		query = "SELECT " + endpointColumns + " FROM endpoints ORDER BY created_at DESC"
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, rows.Err()
}

// GetByID returns an endpoint by ID
func (r *EndpointRepository) GetByID(ctx context.Context, id string) (*Endpoint, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+endpointColumns+" FROM endpoints WHERE id = $1", id)
	ep, err := scanEndpoint(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ep, nil
}

// RegisterInventory consumes one enrollment code and records a Windows reporter.
// A failed insert rolls the code consumption back. This does not issue agent credentials.
func (r *EndpointRepository) RegisterInventory(ctx context.Context, in InventoryInput) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("inventory store is unavailable")
	}
	if in.OrganizationID == "" || in.Hostname == "" || in.OSVersion == "" || len(in.Posture) == 0 || in.ObservedAt.IsZero() {
		return "", errors.New("inventory report is incomplete")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var codeID string
	err = tx.QueryRowContext(ctx, `UPDATE enrollment_codes
		SET used_at = $3
		WHERE organization_id = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING id`, in.OrganizationID, in.CodeDigest[:], in.ObservedAt).Scan(&codeID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInventoryCode
	}
	if err != nil {
		return "", err
	}
	var id string
	err = tx.QueryRowContext(ctx, `INSERT INTO endpoints
		(organization_id, hostname, platform, platform_version, enrollment_status, last_seen_at, metadata)
		VALUES ($1, $2, 'windows', $3, 'inventory', $4, $5::jsonb)
		RETURNING id`, in.OrganizationID, in.Hostname, in.OSVersion, in.ObservedAt, string(in.Posture)).Scan(&id)
	if err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

type endpointScanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(sc endpointScanner) (*Endpoint, error) {
	var ep Endpoint
	var seen sql.NullTime
	var meta []byte
	if err := sc.Scan(&ep.ID, &ep.OrganizationID, &ep.Hostname, &ep.Platform, &ep.EnrollmentStatus, &ep.PlatformVersion, &seen, &meta); err != nil {
		return nil, err
	}
	if seen.Valid {
		observed := seen.Time
		ep.LastSeenAt = &observed
	}
	if ep.EnrollmentStatus == InventoryStatus && len(meta) > 0 && string(meta) != "{}" && string(meta) != "null" {
		ep.Posture = append(json.RawMessage(nil), meta...)
	}
	return &ep, nil
}

// OrganizationForEndpoint returns the persisted tenant owner used when
// authorizing endpoint-bound remote actions.
func (r *EndpointRepository) OrganizationForEndpoint(ctx context.Context, id string) (string, error) {
	endpoint, err := r.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	if endpoint == nil {
		return "", nil
	}
	return endpoint.OrganizationID, nil
}

// Update modifies an existing endpoint
func (r *EndpointRepository) Update(ctx context.Context, ep *Endpoint) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE endpoints
		SET hostname = $1, platform = $2, enrollment_status = $3, updated_at = NOW()
		WHERE id = $4`,
		ep.Hostname, ep.Platform, ep.EnrollmentStatus, ep.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes an endpoint
func (r *EndpointRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM endpoints WHERE id = $1", id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
