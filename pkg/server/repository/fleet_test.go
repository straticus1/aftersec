package repository

import (
	"context"
	"testing"
	"time"

	"aftersec/pkg/fleetcorrelation"
)

func TestFleetAlertPersistRejectsIncompleteAlert(t *testing.T) {
	repo := NewFleetAlertRepository(nil)
	err := repo.Persist(context.Background(), fleetcorrelation.Alert{
		TenantID: "org", Kind: fleetcorrelation.FileHash, Value: "abc", DetectedAt: time.Now(),
	})
	if err != fleetcorrelation.ErrPersist {
		t.Fatalf("%v", err)
	}
}
