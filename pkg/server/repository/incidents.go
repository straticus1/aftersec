package repository

import (
	"context"
	"database/sql"
	"fmt"

	"aftersec/pkg/selfprotect"
)

type SilenceIncidentRepository struct {
	db *sql.DB
}

func NewSilenceIncidentRepository(db *sql.DB) *SilenceIncidentRepository {
	return &SilenceIncidentRepository{db: db}
}

// RecordSilence persists an endpoint-silence incident under forced tenant RLS.
// Threats: a missing tenant context or failed insert is surfaced to the tracker;
// silence is never treated as successfully recorded when persistence fails.
func (r *SilenceIncidentRepository) RecordSilence(incident selfprotect.Incident) error {
	if r == nil || r.db == nil || incident.TenantID == "" || incident.HardwareID == "" ||
		incident.LastSeen.IsZero() || incident.DetectedAt.IsZero() {
		return fmt.Errorf("valid silence incident and database are required")
	}
	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('aftersec.organization_id', $1, true)`, incident.TenantID); err != nil {
		return fmt.Errorf("set incident tenant: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO agent_silence_incidents
			(organization_id, hardware_id, last_seen_at, detected_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (organization_id, hardware_id, last_seen_at) DO NOTHING`,
		incident.TenantID, incident.HardwareID, incident.LastSeen, incident.DetectedAt); err != nil {
		return fmt.Errorf("insert silence incident: %w", err)
	}
	return tx.Commit()
}
