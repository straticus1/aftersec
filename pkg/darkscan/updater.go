package darkscan

import (
	"context"
	"log"
	"time"
)

// StartAutoUpdater launches a background goroutine that periodically updates enabled engines.
// The context should be the daemon's lifecycle context so it shuts down cleanly.
func StartAutoUpdater(ctx context.Context, client interface{ UpdateEngines(context.Context) error }, interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	// Run initially in the background to not block startup
	go func() {
		log.Println("📥 [DarkScan] Starting initial engine definition updates...")
		updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		if err := client.UpdateEngines(updateCtx); err != nil {
			log.Printf("⚠️ [DarkScan] Initial definition update failed: %v", err)
		} else {
			log.Println("✅ [DarkScan] Engine definitions updated successfully.")
		}
		cancel()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Println("📥 [DarkScan] Periodic engine definition update...")
				updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				if err := client.UpdateEngines(updateCtx); err != nil {
					log.Printf("⚠️ [DarkScan] Definition update failed: %v", err)
				}
				cancel()
			}
		}
	}()
}
