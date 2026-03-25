package repository

import (
	"context"
	"database/sql"
)

type Organization struct {
	ID          string
	Name        string
	Slug        string
	LicenseTier string
}

type OrganizationRepository struct {
	db *sql.DB
}

func NewOrganizationRepository(db *sql.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

// GetByID returns an Organization natively mapped from Postgres
func (r *OrganizationRepository) GetByID(ctx context.Context, id string) (*Organization, error) {
	row := r.db.QueryRowContext(ctx, "SELECT id, name, slug, license_tier FROM organizations WHERE id = $1", id)
	var org Organization
	err := row.Scan(&org.ID, &org.Name, &org.Slug, &org.LicenseTier)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &org, nil
}

// List returns all organizations with optional filtering
func (r *OrganizationRepository) List(ctx context.Context) ([]*Organization, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, name, slug, license_tier FROM organizations ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		var org Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.Slug, &org.LicenseTier); err != nil {
			return nil, err
		}
		orgs = append(orgs, &org)
	}
	return orgs, rows.Err()
}

// Create inserts a new organization
func (r *OrganizationRepository) Create(ctx context.Context, org *Organization) error {
	return r.db.QueryRowContext(ctx, `
		INSERT INTO organizations (name, slug, license_tier)
		VALUES ($1, $2, $3) RETURNING id`,
		org.Name, org.Slug, org.LicenseTier).Scan(&org.ID)
}

// Update modifies an existing organization
func (r *OrganizationRepository) Update(ctx context.Context, org *Organization) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE organizations
		SET name = $1, slug = $2, license_tier = $3, updated_at = NOW()
		WHERE id = $4`,
		org.Name, org.Slug, org.LicenseTier, org.ID)
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

// Delete removes an organization
func (r *OrganizationRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM organizations WHERE id = $1", id)
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
