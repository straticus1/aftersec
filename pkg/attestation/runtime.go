package attestation

import (
	"database/sql"
	"fmt"
	"time"
)

type RuntimeConfig struct {
	Mode                string
	CACertificateFile   string
	CAPrivateKeyFile    string
	CertificateLifetime time.Duration
	CodeLifetime        time.Duration
}

type Runtime struct {
	Service          *EnrollmentService
	DevelopmentCAPEM []byte
}

// BuildRuntime constructs enrollment dependencies without implicit fallbacks.
// Threats: production cannot start without persistent code storage, CA material,
// and an attestation verifier. Development trust is available only by explicitly
// selecting development mode and is never persisted or reused automatically.
func BuildRuntime(config RuntimeConfig, db *sql.DB, verifier Verifier) (*Runtime, error) {
	if config.CertificateLifetime <= 0 {
		return nil, fmt.Errorf("positive enrollment certificate lifetime is required")
	}
	switch config.Mode {
	case "production":
		if db == nil || verifier == nil || config.CACertificateFile == "" || config.CAPrivateKeyFile == "" {
			return nil, fmt.Errorf("production enrollment requires database, CA certificate/key, and attestation verifier")
		}
		issuer, err := LoadCAIssuer(config.CACertificateFile, config.CAPrivateKeyFile, time.Now, config.CertificateLifetime)
		if err != nil {
			return nil, err
		}
		return &Runtime{Service: NewEnrollmentService(NewPostgresCodeStore(db), verifier, issuer, time.Now)}, nil
	case "development":
		if verifier == nil {
			return nil, fmt.Errorf("development enrollment still requires an explicit verifier")
		}
		issuer, caPEM, err := NewDevelopmentIssuer(time.Now, config.CertificateLifetime)
		if err != nil {
			return nil, err
		}
		return &Runtime{
			Service:          NewEnrollmentService(NewMemoryCodeStore(), verifier, issuer, time.Now),
			DevelopmentCAPEM: caPEM,
		}, nil
	default:
		return nil, fmt.Errorf("enrollment mode must be explicitly production or development")
	}
}
