package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	grpcapi "aftersec/pkg/api/grpc"
)

// mockEnterprise implements enterpriseServer for tests.
type mockEnterprise struct {
	dispatched []*grpcapi.ServerCommand
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

func testRouter(d enterpriseServer) *Router {
	return &Router{enterpriseSrv: d}
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

	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-offline", Action: "SCAN"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body))
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

func TestHandleEndpointAction_Success(t *testing.T) {
	d := &mockEnterprise{}
	router := testRouter(d)

	body, _ := json.Marshal(EndpointActionRequest{EndpointID: "ep-online", Action: "ISOLATE", Payload: "dGVzdA=="})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/action", bytes.NewReader(body))
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
	if d.dispatched[0].Action != "ISOLATE" {
		t.Errorf("expected action ISOLATE, got %q", d.dispatched[0].Action)
	}
}
