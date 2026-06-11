package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aftersec/pkg/server/auth"
)

func newTestRouter(t *testing.T) (*Router, *auth.JWTManager) {
	t.Helper()
	// Keep Stripe out of the picture regardless of the host environment.
	t.Setenv("STRIPE_SECRET_KEY", "")
	jwtManager := auth.NewJWTManager("test-secret", time.Hour)
	return NewRouter(jwtManager, nil, nil, nil, nil, nil, nil), jwtManager
}

func TestRouter_HealthIsPublic(t *testing.T) {
	router, _ := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unauthenticated health check, got %d", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body["status"] != "operational" {
		t.Errorf("expected status=operational, got %q", body["status"])
	}
}

func TestRouter_ProtectedRoutesRejectMissingAuth(t *testing.T) {
	router, _ := newTestRouter(t)
	protected := []string{
		"/api/v1/organizations",
		"/api/v1/endpoints",
		"/api/v1/scans",
		"/api/v1/bandit/query",
		"/api/v1/darkweb/alerts",
		"/api/v1/ai/budget",
		"/api/v1/organizations/upgrade",
		"/api/v1/endpoints/action",
		"/api/v1/sigma/deploy",
		"/api/v1/misp/sync",
		"/api/v1/detonate",
	}
	for _, path := range protected {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401 without auth, got %d", path, w.Code)
		}
	}
}

func TestRouter_RejectsMalformedAuthHeader(t *testing.T) {
	router, _ := newTestRouter(t)
	for _, header := range []string{"Bearer", "Basic abc123", "garbage"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints", nil)
		req.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: expected 401, got %d", header, w.Code)
		}
	}
}

func TestRouter_RejectsForgedToken(t *testing.T) {
	router, _ := newTestRouter(t)
	// Token signed with the wrong secret must be rejected.
	otherManager := auth.NewJWTManager("attacker-secret", time.Hour)
	token, err := otherManager.GenerateToken("user-1", "org-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for token signed with wrong secret, got %d", w.Code)
	}
}

func TestRouter_ValidTokenPassesMiddleware(t *testing.T) {
	router, jwtManager := newTestRouter(t)
	token, err := jwtManager.GenerateToken("user-1", "org-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	// GET on the action endpoint returns 405 from the handler itself —
	// proving the request made it through the auth middleware.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints/action", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 from handler after auth, got %d", w.Code)
	}
}

func TestRouter_OptionalRoutesAbsentWithoutDeps(t *testing.T) {
	router, _ := newTestRouter(t)
	// ClamAV and DarkScan handlers were not configured, so their routes
	// must not exist at all.
	for _, path := range []string{
		"/api/v1/clamav/definitions/version",
		"/api/v1/darkscan/status",
		"/api/v1/darkscan/scan",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404 when handler not configured, got %d", path, w.Code)
		}
	}
}

func TestWithRateLimit_NilLimiterPassesThrough(t *testing.T) {
	router, _ := newTestRouter(t)
	called := false
	handler := router.withRateLimit(nil, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Error("expected handler to be called with nil limiter")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port string
	}{
		{"192.168.1.1:8080", "192.168.1.1", "8080"},
		{"[::1]:443", "[::1]", "443"},
		{"noport", "noport", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		host, port, _ := splitHostPort(c.in)
		if host != c.host || port != c.port {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)", c.in, host, port, c.host, c.port)
		}
	}
}
