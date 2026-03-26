package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Scan struct {
	ID            string
	OrganizationID string
	EndpointID    string
	ClientScanID  string
	ScanType      string
	Status        string
	StartedAt     time.Time
	CompletedAt   *time.Time
	FindingsCount int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	PassedCount   int
	CreatedAt     time.Time
}

type ScanRepository struct {
	db *sql.DB
}

func NewScanRepository(db *sql.DB) *ScanRepository {
	return &ScanRepository{db: db}
}

// Create inserts a new scan
func (r *ScanRepository) Create(ctx context.Context, scan *Scan) error {
	return r.db.QueryRowContext(ctx, `
		INSERT INTO scans (
			organization_id, endpoint_id, client_scan_id, scan_type, status,
			started_at, completed_at, findings_count, critical_count, high_count,
			medium_count, low_count, passed_count
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, created_at`,
		scan.OrganizationID, scan.EndpointID, scan.ClientScanID, scan.ScanType, scan.Status,
		scan.StartedAt, scan.CompletedAt, scan.FindingsCount, scan.CriticalCount, scan.HighCount,
		scan.MediumCount, scan.LowCount, scan.PassedCount,
	).Scan(&scan.ID, &scan.CreatedAt)
}

// GetByID returns a scan by ID
func (r *ScanRepository) GetByID(ctx context.Context, id string) (*Scan, error) {
	var scan Scan
	err := r.db.QueryRowContext(ctx, `
		SELECT id, organization_id, endpoint_id, client_scan_id, scan_type, status,
			started_at, completed_at, findings_count, critical_count, high_count,
			medium_count, low_count, passed_count, created_at
		FROM scans WHERE id = $1`, id).Scan(
		&scan.ID, &scan.OrganizationID, &scan.EndpointID, &scan.ClientScanID, &scan.ScanType, &scan.Status,
		&scan.StartedAt, &scan.CompletedAt, &scan.FindingsCount, &scan.CriticalCount, &scan.HighCount,
		&scan.MediumCount, &scan.LowCount, &scan.PassedCount, &scan.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &scan, nil
}

// List returns scans with optional filtering
func (r *ScanRepository) List(ctx context.Context, endpointID, orgID string, limit int) ([]*Scan, error) {
	query := `
		SELECT id, organization_id, endpoint_id, client_scan_id, scan_type, status,
			started_at, completed_at, findings_count, critical_count, high_count,
			medium_count, low_count, passed_count, created_at
		FROM scans
		WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if orgID != "" {
		query += fmt.Sprintf(" AND organization_id = $%d", argIdx)
		args = append(args, orgID)
		argIdx++
	}

	if endpointID != "" {
		query += fmt.Sprintf(" AND endpoint_id = $%d", argIdx)
		args = append(args, endpointID)
		argIdx++
	}

	query += " ORDER BY started_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, limit)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*Scan
	for rows.Next() {
		var scan Scan
		if err := rows.Scan(
			&scan.ID, &scan.OrganizationID, &scan.EndpointID, &scan.ClientScanID, &scan.ScanType, &scan.Status,
			&scan.StartedAt, &scan.CompletedAt, &scan.FindingsCount, &scan.CriticalCount, &scan.HighCount,
			&scan.MediumCount, &scan.LowCount, &scan.PassedCount, &scan.CreatedAt,
		); err != nil {
			return nil, err
		}
		scans = append(scans, &scan)
	}
	return scans, rows.Err()
}
