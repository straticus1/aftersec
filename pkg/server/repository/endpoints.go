package repository

import (
	"context"
	"database/sql"
)

type Endpoint struct {
	ID               string
	OrganizationID   string
	Hostname         string
	Platform         string
	EnrollmentStatus string
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
	row := r.db.QueryRowContext(ctx, "SELECT id, organization_id, hostname, platform, enrollment_status FROM endpoints WHERE hostname = $1 LIMIT 1", hostname)
	var ep Endpoint
	err := row.Scan(&ep.ID, &ep.OrganizationID, &ep.Hostname, &ep.Platform, &ep.EnrollmentStatus)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &ep, nil
}

// List returns all endpoints with optional organization filter
func (r *EndpointRepository) List(ctx context.Context, orgID string) ([]*Endpoint, error) {
	var query string
	var args []interface{}

	if orgID != "" {
		query = "SELECT id, organization_id, hostname, platform, enrollment_status FROM endpoints WHERE organization_id = $1 ORDER BY created_at DESC"
		args = append(args, orgID)
	} else {
		query = "SELECT id, organization_id, hostname, platform, enrollment_status FROM endpoints ORDER BY created_at DESC"
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		var ep Endpoint
		if err := rows.Scan(&ep.ID, &ep.OrganizationID, &ep.Hostname, &ep.Platform, &ep.EnrollmentStatus); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, &ep)
	}
	return endpoints, rows.Err()
}

// GetByID returns an endpoint by ID
func (r *EndpointRepository) GetByID(ctx context.Context, id string) (*Endpoint, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, organization_id, hostname, platform, enrollment_status FROM endpoints WHERE id = $1", id)
	var ep Endpoint
	err := row.Scan(&ep.ID, &ep.OrganizationID, &ep.Hostname, &ep.Platform, &ep.EnrollmentStatus)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &ep, nil
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
