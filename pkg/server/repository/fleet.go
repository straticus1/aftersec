package repository

import (
	"context"
	"database/sql"
	"fmt"

	"aftersec/pkg/fleetcorrelation"
	"github.com/lib/pq"
)

type FleetAlertRepository struct {
	db *sql.DB
}

func NewFleetAlertRepository(db *sql.DB) *FleetAlertRepository {
	return &FleetAlertRepository{db: db}
}

// Persist stores one cross-endpoint alert under forced tenant isolation.
// Threats: a missing tenant, a short endpoint set, or a failed insert is
// returned to the stream so the event is not acknowledged.
func (r *FleetAlertRepository) Persist(ctx context.Context, alert fleetcorrelation.Alert) error {
	if r == nil || r.db == nil || alert.TenantID == "" || alert.Kind == "" || alert.Value == "" ||
		len(alert.Endpoints) < 2 || alert.DetectedAt.IsZero() {
		return fleetcorrelation.ErrPersist
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('aftersec.organization_id', $1, true)`, alert.TenantID); err != nil {
		return fmt.Errorf("set fleet tenant: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO fleet_correlation_alerts
			(organization_id, kind, value, endpoints, detected_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (organization_id, kind, value, detected_at) DO NOTHING`,
		alert.TenantID, string(alert.Kind), alert.Value, pq.Array(alert.Endpoints), alert.DetectedAt); err != nil {
		return fmt.Errorf("insert fleet alert: %w", err)
	}
	return tx.Commit()
}
