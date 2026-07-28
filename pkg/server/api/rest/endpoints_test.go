package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/response"
	"aftersec/pkg/server/auth"
)

// mockEnterprise implements enterpriseServer for tests.
type mockEnterprise struct {
	dispatched  []*grpcapi.ServerCommand
	dispatchErr error
}

func (m *mockEnterprise) DispatchCommand(_ string, cmd *grpcapi.ServerCommand) error {
	if m.dispatchErr != nil {
		return m.dispatchErr
	}
	m.dispatched = append(m.dispatched, cmd)
	return nil
}

func (m *mockEnterprise) SetPendingSigmaRule(_ string) {}

type mockActionMinter struct {
	request response.MintRequest
	token   string
	err     error
}

type mockActionAudit struct {
	event response.AuditEvent
	actor string
	err   error
}

func (m *mockActionAudit) AppendDispatch(_ context.Context, event response.AuditEvent, actor string) error {
	m.event = event
	m.actor = actor
	return m.err
}

func (m *mockActionMinter) Mint(_ context.Context, request response.MintRequest) (string, error) {
	m.request = request
	return m.token, m.err
}

func testRouter(d enterpriseServer) *Router {
	return &Router{
		enterpriseSrv: d,
		actionMinter:  &mockActionMinter{token: "signed-token"},
		actionAudit:   &mockActionAudit{},
	}
}

func authorizedRequest(t *testing.T, method, target string, body io.Reader, org, role string) *http.Request {
	t.Helper()
	manager := auth.NewJWTManager("test-secret", time.Minute)
	token, err := manager.GenerateToken("user-1", org, role)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer "+token)
	var authorized *http.Request
	manager.HTTPMiddleware(func(_ http.ResponseWriter, request *http.Request) {
		authorized = request
	}).ServeHTTP(httptest.NewRecorder(), req)
	if authorized == nil {
		t.Fatal("test request was not authorized")
	}
	return authorized
}

func TestHandleEndpointAction_MethodNotAllowed(t *testing.T) {
	router := testRouter(&mockEnterprise{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints/action", nil)
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleEndpointAction_InvalidJSON(t *testing.T) {
	router := testRouter(&mockEnterprise{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/action", bytes.NewBufferString("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleEndpointAction_MissingEndpointID(t *testing.T) {
	router := testRouter(&mockEnterprise{})
	body, _ := json.Marshal(EndpointActionRequest{Action: "SCAN"}) // no endpoint_id
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleEndpointAction_MissingAction(t *testing.T) {
	router := testRouter(&mockEnterprise{})
	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-1"}) // no action
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleEndpointAction_EndpointOffline(t *testing.T) {
	d := &mockEnterprise{dispatchErr: errors.New(`endpoint "ep-offline" has no active command stream`)}
	router := testRouter(d)

	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-offline", Action: response.ActionQuarantine})
	req := authorizedRequest(t, http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body), "org-1", "security_operator")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if success, _ := resp["success"].(bool); success {
		t.Error("expected success=false in response body")
	}
}

func TestHandleEndpointAction_RequiresValidatedClaims(t *testing.T) {
	router := testRouter(&mockEnterprise{})
	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-1", Action: response.ActionQuarantine})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body))
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleEndpointAction_DerivesAuthorizationFromJWT(t *testing.T) {
	dispatcher := &mockEnterprise{}
	minter := &mockActionMinter{token: "signed-token"}
	audit := &mockActionAudit{}
	router := &Router{enterpriseSrv: dispatcher, actionMinter: minter, actionAudit: audit}
	body, _ := json.Marshal(EndpointActionRequest{
		EndpointID: "ep-1",
		Action:     response.ActionCollectFile,
		Arguments:  map[string]string{"path": "/tmp/evidence"},
	})
	req := authorizedRequest(t, http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body), "org-trusted", "security_operator")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if minter.request.TenantID != "org-trusted" || minter.request.Role != "security_operator" ||
		minter.request.EndpointID != "ep-1" || minter.request.Action != response.ActionCollectFile {
		t.Fatalf("unexpected mint request: %+v", minter.request)
	}
	if audit.event.Status != "DISPATCH_REQUESTED" || audit.actor != "user-1" {
		t.Fatalf("unexpected audit record: %+v actor=%q", audit.event, audit.actor)
	}
}

func TestHandleEndpointAction_DoesNotDispatchWhenMintingFails(t *testing.T) {
	dispatcher := &mockEnterprise{}
	router := &Router{
		enterpriseSrv: dispatcher,
		actionMinter:  &mockActionMinter{err: errors.New("tenant mismatch")},
		actionAudit:   &mockActionAudit{},
	}
	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "cross-tenant", Action: response.ActionQuarantine})
	req := authorizedRequest(t, http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body), "org-1", "security_operator")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if len(dispatcher.dispatched) != 0 {
		t.Fatal("unauthorized action must not be dispatched")
	}
}

func TestHandleEndpointAction_DoesNotDispatchWhenAuditFails(t *testing.T) {
	dispatcher := &mockEnterprise{}
	router := &Router{
		enterpriseSrv: dispatcher,
		actionMinter:  &mockActionMinter{token: "signed-token"},
		actionAudit:   &mockActionAudit{err: errors.New("database unavailable")},
	}
	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-1", Action: response.ActionQuarantine})
	req := authorizedRequest(t, http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body), "org-1", "security_operator")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	if len(dispatcher.dispatched) != 0 {
		t.Fatal("action was dispatched without durable audit record")
	}
}

func TestHandleEndpointAction_Success(t *testing.T) {
	d := &mockEnterprise{}
	router := testRouter(d)

	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-online", Action: response.ActionQuarantine, Arguments: map[string]string{"control_host": "control.example"}})
	req := authorizedRequest(t, http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body), "org-1", "security_operator")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.handleEndpointAction(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if success, _ := resp["success"].(bool); !success {
		t.Error("expected success=true in response body")
	}
	if resp["command_id"] == "" {
		t.Error("expected non-empty command_id in response")
	}
	if resp["status"] != "command_queued" {
		t.Errorf("expected status=command_queued, got %v", resp["status"])
	}

	if len(d.dispatched) != 1 {
		t.Fatalf("expected 1 dispatched command, got %d", len(d.dispatched))
	}
	if d.dispatched[0].Action != "REMOTE_ACTION" || d.dispatched[0].Payload != "signed-token" {
		t.Errorf("expected signed REMOTE_ACTION, got action=%q payload=%q", d.dispatched[0].Action, d.dispatched[0].Payload)
	}
}
