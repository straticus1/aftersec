package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

type Client struct {
	DB *sql.DB
}

// NewPostgresClient initializes a connection pool to the management databases
func NewPostgresClient(dsn string) (*Client, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	log.Println("Successfully connected to PostgreSQL")

	return &Client{DB: db}, nil
}

// Close gracefully terminates the pool
func (c *Client) Close() error {
	if c.DB != nil {
		return c.DB.Close()
	}
	return nil
}

// RunMigrations applies pending SQL schemas
func (c *Client) RunMigrations(schemaPath string) error {
	log.Printf("Migrating database using %s", schemaPath)
	content, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("failed to read schema file: %w", err)
	}
	_, err = c.DB.Exec(string(content))
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	return nil
}
