//go:build ignore

package main

import (
	"fmt"
	"time"

	"aftersec/pkg/server/auth"
)

func main() {
	// Use the same secret as the test server
	jwtManager := auth.NewJWTManager("super-secret-key-12345", 24*time.Hour)

	// Generate token for a test user
	token, err := jwtManager.GenerateToken("test-user", "admin", "tenant-default")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Println(token)
}
