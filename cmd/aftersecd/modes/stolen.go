package modes

import (
	"context"
	"log"
	"os"
	"time"

	"aftersec/pkg/client"
	"aftersec/pkg/display"
)

func socketFrom(cfg *client.ClientConfig) string {
	if cfg != nil && cfg.Daemon.DisplaySocket != "" {
		return cfg.Daemon.DisplaySocket
	}
	return os.Getenv("AFTERSEC_DISPLAY_SOCKET")
}

func applyStolenHeartbeat(socketPath, action string) {
	if socketPath == "" {
		log.Print("stolen camera is not configured")
		return
	}
	session := display.NewClient(socketPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if action == "MARK_STOLEN" {
		err = session.Arm(ctx)
	} else {
		err = session.Disarm(ctx)
	}
	if err != nil {
		log.Printf("stolen camera update failed: %v", err)
	}
}

func uploadStolenPhotos(grpcClient *client.EnterpriseClient, session *display.Client, tenant, endpoint string) {
	if grpcClient == nil || session == nil || tenant == "" || endpoint == "" {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		id, frame, err := session.NextStolen(ctx)
		if err != nil || id == "" || len(frame) == 0 {
			cancel()
			continue
		}
		env, err := display.Envelope(frame)
		if err != nil {
			cancel()
			log.Printf("stolen camera frame rejected: %v", err)
			continue
		}
		stored, err := grpcClient.SendStolenCamera(ctx, tenant, endpoint, string(env))
		cancel()
		if err != nil {
			log.Printf("stolen camera upload failed: %v", err)
			continue
		}
		if !stored {
			continue
		}
		ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err = session.AckStolen(ackCtx, id); err != nil {
			log.Printf("stolen camera ack failed: %v", err)
		}
		ackCancel()
	}
}
