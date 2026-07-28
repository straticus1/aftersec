package main

import (
	"context"
	"crypto/ed25519"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/attestation"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/response"
	"aftersec/pkg/selfprotect"
	"aftersec/pkg/server/api/rest"
	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/clamav"
	"aftersec/pkg/server/database"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
	"aftersec/pkg/server/tlsconfig"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

func main() {
	log.Println("Starting AfterSec Management Server...")

	// 1. Initialize DB
	dbUrl := os.Getenv("DATABASE_URL")
	if dbUrl == "" {
		dbUrl = "postgres://postgres:postgres@localhost:5432/aftersec?sslmode=disable"
	}
	dbClient, err := database.NewPostgresClient(dbUrl)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbClient.Close()

	if err := dbClient.RunMigrations("migrations/001_initial_schema.up.sql"); err != nil {
		log.Fatalf("Core database migration failed: %v", err)
	}
	if err := dbClient.RunMigrations("migrations/002_attested_enrollment.up.sql"); err != nil {
		log.Fatalf("Attested enrollment migration failed: %v", err)
	}
	if err := dbClient.RunMigrations("migrations/003_remote_response_audit.up.sql"); err != nil {
		log.Fatalf("Remote response migration failed: %v", err)
	}
	if err := dbClient.RunMigrations("migrations/004_agent_silence_incidents.up.sql"); err != nil {
		log.Fatalf("Agent silence incident migration failed: %v", err)
	}
	if err := dbClient.RunMigrations("migrations/005_remote_response_audit_lifecycle.up.sql"); err != nil {
		log.Fatalf("Remote response lifecycle migration failed: %v", err)
	}

	repos := repository.NewRepositories(dbClient.DB)

	// 1.5 Setup Auth
	jwtManager := auth.NewJWTManager("super-secret-key-12345", 24*time.Hour)

	// 1.6 Initialize ClamAV Definition Updater (optional)
	var clamavStorage *clamav.Storage
	var clamavUpdater *clamav.Updater

	clamavEnabled := os.Getenv("CLAMAV_UPDATER_ENABLED")
	if clamavEnabled == "true" {
		storagePath := os.Getenv("CLAMAV_STORAGE_PATH")
		if storagePath == "" {
			storagePath = "/var/aftersec/clamav-defs"
		}

		clamavStorage = clamav.NewStorage(storagePath)

		var err error
		clamavUpdater, err = clamav.NewUpdater(storagePath, 4*time.Hour)
		if err != nil {
			log.Printf("Warning: ClamAV updater initialization failed: %v", err)
		} else {
			log.Println("ClamAV definition updater initialized")
			// Start updater in background
			go func() {
				if err := clamavUpdater.Start(context.Background()); err != nil {
					log.Printf("ClamAV updater stopped: %v", err)
				}
			}()
		}
	} else {
		log.Println("ClamAV definition updater disabled (set CLAMAV_UPDATER_ENABLED=true to enable)")
	}

	journalPath := os.Getenv("EVENT_JOURNAL_PATH")
	if journalPath == "" {
		journalPath = filepath.Join("data", "server-events.db")
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0700); err != nil {
		log.Fatalf("Failed to create event journal directory: %v", err)
	}
	enterpriseSrv, err := grpcserver.NewDurableServer(repos, journalPath, 1<<30)
	if err != nil {
		log.Fatalf("Failed to initialize durable event journal: %v", err)
	}
	defer enterpriseSrv.Close()
	enrollmentRuntime, certificateTTL, err := attestation.BuildRuntimeFromEnvironment(os.Getenv, dbClient.DB)
	if err != nil {
		log.Fatalf("Failed to initialize attested enrollment: %v", err)
	}
	enterpriseSrv.SetEnrollmentService(enrollmentRuntime.Service, certificateTTL)
	heartbeatTracker := selfprotect.NewTracker(5*time.Minute, 2*time.Minute, repos.SilenceIncidents)
	enterpriseSrv.SetHeartbeatTracker(heartbeatTracker)
	enterpriseSrv.SetCommandResultAudit(repos.RemoteActionAudit)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for checkedAt := range ticker.C {
			if err := enterpriseSrv.CheckHeartbeatSilence(checkedAt); err != nil {
				log.Printf("Heartbeat silence detection failed closed: %v", err)
			}
		}
	}()

	// Initialize DarkScan client
	darkscanCfg := darkscan.DefaultConfig()
	darkscanCfg.Enabled = true
	darkscanClient, err := darkscan.NewClient(darkscanCfg)
	if err != nil {
		log.Printf("Warning: DarkScan initialization failed: %v", err)
		darkscanClient = nil
	}

	// Optional Redis client for rate limiting
	var redisClient *redis.Client
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Printf("Warning: invalid REDIS_URL, rate limiting disabled: %v", err)
		} else {
			redisClient = redis.NewClient(opt)
			log.Println("Redis rate limiting enabled")
		}
	}

	// 2. Start basic REST API
	mux := rest.NewRouter(jwtManager, repos, enterpriseSrv, clamavStorage, clamavUpdater, darkscanClient, redisClient)
	mux.SetActionAudit(repos.RemoteActionAudit)
	if keyPath := os.Getenv("REMOTE_ACTION_SIGNING_KEY_PATH"); keyPath != "" {
		key, keyErr := os.ReadFile(keyPath)
		if keyErr != nil || len(key) != ed25519.PrivateKeySize {
			log.Printf("Remote response disabled: signing key is unavailable or invalid")
		} else {
			mux.SetActionMinter(response.NewActionMinter(ed25519.PrivateKey(key), repos.Endpoints, 2*time.Minute, time.Now))
			log.Println("Signed remote response enabled")
		}
	} else {
		log.Println("Remote response disabled: REMOTE_ACTION_SIGNING_KEY_PATH is not configured")
	}

	go func() {
		log.Println("Listening for REST API on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Fatalf("REST API failed: %v", err)
		}
	}()

	// 3. Start gRPC server with production TLS + mTLS
	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Fatalf("Failed to listen for gRPC on :9090: %v", err)
	}

	var tlsCfg tlsconfig.Config
	if os.Getenv("MTLS_ENABLED") == "true" {
		log.Println("mTLS enabled: requiring client certificates")
		tlsCfg = tlsconfig.DefaultServerConfig()
	} else {
		log.Println("mTLS disabled: development mode")
		tlsCfg = tlsconfig.DevServerConfig()
	}

	creds, err := tlsconfig.NewServerTLSConfig(tlsCfg)
	if err != nil {
		log.Fatalf("Failed to configure TLS: %v", err)
	}

	grpcServerInstance := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(jwtManager.GRPCUnaryInterceptor),
		grpc.StreamInterceptor(jwtManager.GRPCStreamInterceptor),
	)

	grpcapi.RegisterEnterpriseServiceServer(grpcServerInstance, enterpriseSrv)

	log.Println("Listening for AfterSec gRPC Endpoints on :9090")
	if err := grpcServerInstance.Serve(lis); err != nil {
		log.Fatalf("gRPC Server failed: %v", err)
	}
}
