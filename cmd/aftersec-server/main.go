package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/server/api/rest"
	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/clamav"
	"aftersec/pkg/server/database"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
	"aftersec/pkg/server/tlsconfig"
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
		log.Printf("Warning: Migrations failed or already applied: %v", err)
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

	// 2. Start basic REST API
	mux := rest.NewRouter(jwtManager, repos, clamavStorage, clamavUpdater)

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
	
	enterpriseSrv := grpcserver.NewServer(repos)
	grpcapi.RegisterEnterpriseServiceServer(grpcServerInstance, enterpriseSrv)

	log.Println("Listening for AfterSec gRPC Endpoints on :9090")
	if err := grpcServerInstance.Serve(lis); err != nil {
		log.Fatalf("gRPC Server failed: %v", err)
	}
}
