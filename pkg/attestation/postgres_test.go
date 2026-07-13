package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func testClientCertificate(t *testing.T, now time.Time) []byte {
	t.Helper()
	issuer, _, err := NewDevelopmentIssuer(func() time.Time { return now }, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := issuer.IssueClientCertificate(context.Background(), VerifiedIdentity{
		OrganizationID: "org-1", HardwareID: "hw-1", Hostname: "host-1", Platform: "linux", PublicKey: publicDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestPostgresCodeStoreConsumesCodeAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewPostgresCodeStore(db)
	digest := sha256.Sum256([]byte("code"))
	now := time.Unix(1000, 0)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE enrollment_codes
		SET used_at = $3
		WHERE organization_id = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING id`)).
		WithArgs("org-1", digest[:], now).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("code-id"))
	if err := store.Consume(context.Background(), "org-1", digest, now); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCodeStoreMapsMissingCodeToInvalid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewPostgresCodeStore(db)
	digest := sha256.Sum256([]byte("replayed"))
	mock.ExpectQuery("UPDATE enrollment_codes").WillReturnError(sql.ErrNoRows)
	if err := store.Consume(context.Background(), "org-1", digest, time.Now()); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("error = %v, want ErrCodeInvalid", err)
	}
}

func TestPostgresCodeStoreFinalizesEnrollmentInOneTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewPostgresCodeStore(db)
	now := time.Unix(1000, 0)
	digest := sha256.Sum256([]byte("code"))
	refreshHash := sha256.Sum256([]byte("refresh"))
	quoteHash := sha256.Sum256([]byte("quote"))
	commit := EnrollmentCommit{
		HardwareID: "hw-1", Hostname: "host-1", Platform: "linux",
		AttestationFingerprint: quoteHash, RefreshTokenHash: refreshHash,
		ClientCertificate: testClientCertificate(t, now),
	}
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE enrollment_codes").
		WithArgs("org-1", digest[:], now).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("code-id"))
	mock.ExpectQuery("INSERT INTO endpoints").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("endpoint-id"))
	mock.ExpectExec("INSERT INTO enrollment_audit").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := store.Finalize(context.Background(), "org-1", digest, now, commit); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCodeStoreRollsBackWhenAuditInsertFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewPostgresCodeStore(db)
	now := time.Unix(1000, 0)
	digest := sha256.Sum256([]byte("code"))
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE enrollment_codes").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("code-id"))
	mock.ExpectQuery("INSERT INTO endpoints").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("endpoint-id"))
	mock.ExpectExec("INSERT INTO enrollment_audit").WillReturnError(errors.New("audit unavailable"))
	mock.ExpectRollback()
	err = store.Finalize(context.Background(), "org-1", digest, now, EnrollmentCommit{
		HardwareID: "hw-1", Platform: "linux", ClientCertificate: testClientCertificate(t, now),
	})
	if err == nil {
		t.Fatal("finalize succeeded when audit insert failed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
