package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aftersec/pkg/server/api/rest"
	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/database"
	"aftersec/pkg/server/repository"
)

func main() {
	log.Println("Starting AfterSec Test Server (REST API only)...")

	// Initialize database
	dbUrl := os.Getenv("DATABASE_URL")
	if dbUrl == "" {
		dbUrl = "postgres://ryan@localhost:5432/aftersec?sslmode=disable"
	}

	dbClient, err := database.NewPostgresClient(dbUrl)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbClient.Close()

	log.Println("Successfully connected to PostgreSQL")

	// Run migrations if schema file exists
	schemaPath := "../../migrations/001_initial_schema.up.sql"
	if _, err := os.Stat(schemaPath); err == nil {
		if err := dbClient.RunMigrations(schemaPath); err != nil {
			log.Printf("Warning: Migrations failed or already applied: %v", err)
		} else {
			log.Println("Database migrations completed")
		}
	}

	repos := repository.NewRepositories(dbClient.DB)

	// Setup JWT manager with test key
	jwtManager := auth.NewJWTManager("super-secret-key-12345", 24*time.Hour)

	// Create router
	mux := rest.NewRouter(jwtManager, repos)

	// Start REST API server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("\nShutting down server...")
		if err := server.Close(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
		os.Exit(0)
	}()

	log.Println("REST API listening on http://localhost:8080")
	log.Println("Press Ctrl+C to stop")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
