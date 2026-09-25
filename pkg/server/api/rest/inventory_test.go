package rest

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aftersec/pkg/response"
	"aftersec/pkg/server/repository"
	"github.com/DATA-DOG/go-sqlmock"
)

func inventoryBody(t *testing.T, extra string) []byte {
	t.Helper()
	body := `{
		"organization_id":"11111111-1111-1111-1111-111111111111",
		"code":"one-time-code",
		"hostname":"ENG-01",
		"os_version":"Windows 11 23H2 22631",
		"last_boot":"2020-01-01T00:00:00Z",
		"checks":[
			{"name":"Defender real-time protection","passed":true},
			{"name":"Windows Firewall profiles","passed":false,"error":"disabled"}
		]` + extra + `}`
	return []byte(body)
}

func TestDecodeInventoryRejectsTampering(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if _, _, err := decodeInventory(inventoryBody(t, ""), now); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		strings.Replace(string(inventoryBody(t, "")), "}", `,"enrollment_status":"active"}`, 1),
		strings.Replace(string(inventoryBody(t, "")), "ENG-01", "bad\nhost", 1),
		strings.Replace(string(inventoryBody(t, "")), "2020-01-01T00:00:00Z", "2099-09-25T12:05:00Z", 1),
		strings.Replace(string(inventoryBody(t, "")), "one-time-code", "short", 1),
		`{"organization_id":"11111111-1111-1111-1111-111111111111","code":"one-time-code","hostname":"ENG-01","os_version":"Windows 11","last_boot":"2026-09-25T11:00:00Z","checks":[]}`,
	} {
		if _, _, err := decodeInventory([]byte(body), now); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestInventoryWindowsConsumesACodeOnce(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	digest := sha256.Sum256([]byte("one-time-code"))
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE enrollment_codes").
		WithArgs("11111111-1111-1111-1111-111111111111", digest[:], sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("code-id"))
	mock.ExpectQuery("INSERT INTO endpoints").
		WithArgs("11111111-1111-1111-1111-111111111111", "ENG-01", "Windows 11 23H2 22631", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("endpoint-id"))
	mock.ExpectCommit()
	router := &Router{repos: &repository.Repositories{Endpoints: repository.NewEndpointRepository(db)}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/windows", bytes.NewReader(inventoryBody(t, "")))
	rec := httptest.NewRecorder()
	router.handleInventoryWindows(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var stored map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored["enrollment_status"] != repository.InventoryStatus || stored["id"] != "endpoint-id" {
		t.Fatal(stored)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE enrollment_codes").WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/inventory/windows", bytes.NewReader(inventoryBody(t, "")))
	rec = httptest.NewRecorder()
	router.handleInventoryWindows(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused code status %d", rec.Code)
	}
}

func TestRemoteActionRefusesInventoryEndpoint(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{
		"id", "organization_id", "hostname", "platform", "enrollment_status", "platform_version", "last_seen_at", "metadata",
	}).AddRow("ep-1", "org-1", "ENG-01", "windows", repository.InventoryStatus, "Windows 11", time.Now(), []byte(`{"last_boot":"2026-09-25T11:00:00Z"}`)))
	minter := &mockActionMinter{err: errCalled}
	router := testRouter(&mockEnterprise{})
	router.actionMinter = minter
	router.repos = &repository.Repositories{Endpoints: repository.NewEndpointRepository(db)}
	body, err := json.Marshal(EndpointActionRequest{EndpointID: "ep-1", Action: response.ActionKillProcess})
	if err != nil {
		t.Fatal(err)
	}
	req := authorizedRequest(t, http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body), "org-1", "security_operator")
	rec := httptest.NewRecorder()
	router.handleEndpointAction(rec, req)
	if rec.Code != http.StatusForbidden || minter.request.EndpointID != "" {
		t.Fatalf("status %d request %+v", rec.Code, minter.request)
	}
}

var errCalled = errInventory
