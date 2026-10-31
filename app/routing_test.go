package goxis_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/middleware"
	"github.com/AndresGT/Goxis/security/token"
)

type testAccessValidator struct {
	claims token.Claims
	err    error
}

func (v testAccessValidator) ValidateAccessToken(string) (token.Claims, error) {
	return v.claims, v.err
}

func TestStaticRouteWinsAndEquivalentPatternsAreRejected(t *testing.T) {
	app := goxis.New()
	group := app.Group("/users")
	if err := group.RegisterRoutes([]goxis.Route{
		{Method: goxis.GET, Path: "/:id", Handler: func(ctx *goxis.Context) error { return ctx.Text(200, "dynamic") }},
		{Method: goxis.GET, Path: "/me", Handler: func(ctx *goxis.Context) error { return ctx.Text(200, "static") }},
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users/me", nil))
	if w.Code != 200 || w.Body.String() != "static" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	if err := group.RegisterRoutes([]goxis.Route{{Method: goxis.GET, Path: "/{slug}", Handler: func(*goxis.Context) error { return nil }}}); err == nil {
		t.Fatal("expected equivalent dynamic route to be rejected")
	}
}

func TestRequestIDIsGeneratedReturnedAndAvailableToHandler(t *testing.T) {
	app := goxis.New()
	var handlerID string
	if err := app.Group("/").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/trace",
		Handler: func(ctx *goxis.Context) error {
			handlerID = ctx.RequestID()
			return ctx.JSON(http.StatusOK, map[string]string{"request_id": handlerID})
		},
	}}); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest(http.MethodGet, "/trace", nil)
		request.Header.Set(goxis.RequestIDHeader, "client-supplied-id")
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		requestID := response.Header().Get(goxis.RequestIDHeader)
		decoded, err := hex.DecodeString(requestID)
		if err != nil || len(decoded) != 16 {
			t.Fatalf("invalid generated request ID %q", requestID)
		}
		if requestID == "client-supplied-id" || handlerID != requestID || seen[requestID] {
			t.Fatalf("request ID mismatch or reuse: response=%q handler=%q", requestID, handlerID)
		}
		var payload struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.RequestID != requestID {
			t.Fatalf("handler body ID=%q header ID=%q", payload.RequestID, requestID)
		}
		seen[requestID] = true
	}
}

func TestProtectedRouteRejectsInvalidTokenBeforeHandler(t *testing.T) {
	app := goxis.New(goxis.WithAuthorizer(middleware.NewRBAC(testAccessValidator{err: token.ErrInvalidToken})))
	called := false
	if err := app.Group("/private").RegisterRoutes([]goxis.Route{{Method: goxis.GET, Path: "/", Protected: true, Handler: func(*goxis.Context) error { called = true; return nil }}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.Header.Set("Authorization", "Bearer invalid")
	app.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d handler_called=%v", w.Code, called)
	}
	assertJSONError(t, w, http.StatusUnauthorized, "unauthorized")
}

func TestRequireAuthReturnsSentinelForCentralJSONTranslation(t *testing.T) {
	app := goxis.New()
	app.Use(middleware.RequireAuth(testAccessValidator{err: token.ErrInvalidToken}))
	if err := app.Group("/").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/private",
		Handler: func(*goxis.Context) error { t.Fatal("handler must not run"); return nil },
	}}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	app.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/private", nil))
	assertJSONError(t, response, http.StatusUnauthorized, "unauthorized")
}

func TestCoreRouteErrorsUseOneJSONEnvelope(t *testing.T) {
	app := goxis.New()
	if err := app.Group("/").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/limited", RateLimit: 1,
		Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, "ok") },
	}}); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		method, path string
		status       int
		code         string
	}{
		{http.MethodGet, "/missing", http.StatusNotFound, "not_found"},
		{http.MethodPost, "/limited", http.StatusMethodNotAllowed, "method_not_allowed"},
	} {
		response := httptest.NewRecorder()
		app.ServeHTTP(response, httptest.NewRequest(check.method, check.path, nil))
		assertJSONError(t, response, check.status, check.code)
	}
	request := httptest.NewRequest(http.MethodGet, "/limited", nil)
	request.RemoteAddr = "192.0.2.77:1000"
	first := httptest.NewRecorder()
	app.ServeHTTP(first, request)
	second := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/limited", nil)
	request.RemoteAddr = "192.0.2.77:1000"
	app.ServeHTTP(second, request)
	assertJSONError(t, second, http.StatusTooManyRequests, "rate_limit_exceeded")
}

func assertJSONError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("status=%d content-type=%q body=%q; want status=%d JSON", response.Code, response.Header().Get("Content-Type"), response.Body.String(), status)
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error != code {
		t.Fatalf("error=%q want=%q", payload.Error, code)
	}
}

func TestProtectedRouteRejectsValidTokenWithoutRequiredRole(t *testing.T) {
	validator := testAccessValidator{claims: token.Claims{UserID: "demo-viewer", Roles: []string{"viewer"}}}
	app := goxis.New(goxis.WithAuthorizer(middleware.NewRBAC(validator)))
	called := false
	if err := app.Group("/admin").RegisterRoutes([]goxis.Route{{Method: goxis.GET, Path: "/", Roles: []string{"admin"}, Handler: func(*goxis.Context) error { called = true; return nil }}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.Header.Set("Authorization", "Bearer valid-viewer-token")
	app.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d handler_called=%v", w.Code, called)
	}
	assertJSONError(t, w, http.StatusForbidden, "forbidden")
}

func TestProtectedRouteAcceptsRequiredRole(t *testing.T) {
	validator := testAccessValidator{claims: token.Claims{UserID: "demo-admin", Roles: []string{"admin"}}}
	authorizer := middleware.NewRBAC(validator, middleware.Role{Name: "admin", Permissions: []string{"*"}})
	app := goxis.New(goxis.WithAuthorizer(authorizer))
	if err := app.Group("/admin").RegisterRoutes([]goxis.Route{{Method: goxis.GET, Path: "/", Roles: []string{"admin"}, Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, "ok") }}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.Header.Set("Authorization", "Bearer valid-admin-token")
	app.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestRateLimitSeparatesUsersAcrossIPsAndNAT(t *testing.T) {
	manager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:           []byte("integration-test-secret-with-32-bytes-minimum"),
		AccessTokenDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	aliceToken, err := manager.GenerateAccessToken(token.Claims{UserID: "user-alice"})
	if err != nil {
		t.Fatal(err)
	}
	bobToken, err := manager.GenerateAccessToken(token.Claims{UserID: "user-bob"})
	if err != nil {
		t.Fatal(err)
	}
	app := goxis.New(goxis.WithAuthorizer(middleware.NewRBAC(manager)))
	if err := app.Group("/limited").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/", Protected: true, RateLimit: 1,
		Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, ctx.Identity()) },
	}}); err != nil {
		t.Fatal(err)
	}

	request := func(tokenValue, remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer "+tokenValue)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		return response
	}

	if response := request(aliceToken, "192.0.2.10:1000"); response.Code != http.StatusOK || response.Body.String() != "user-alice" {
		t.Fatalf("first Alice request: status=%d body=%q", response.Code, response.Body.String())
	}
	if response := request(aliceToken, "198.51.100.20:2000"); response.Code != http.StatusTooManyRequests {
		t.Fatalf("Alice should share her limit across IPs; status=%d", response.Code)
	}
	if response := request(bobToken, "198.51.100.20:2000"); response.Code != http.StatusOK || response.Body.String() != "user-bob" {
		t.Fatalf("Bob should have an independent limit behind the same IP; status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestRateLimitFallsBackToIPWithoutVerifiedIdentity(t *testing.T) {
	manager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:           []byte("integration-test-secret-with-32-bytes-minimum"),
		AccessTokenDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	app := goxis.New(goxis.WithAuthorizer(middleware.NewRBAC(manager)))
	if err := app.Group("/limited").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/", RateLimit: 1,
		Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, "ok") },
	}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = "192.0.2.55:1000"
		req.Header.Set("Authorization", "Bearer invalid-token")
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		want := http.StatusOK
		if i == 1 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("request %d status=%d want=%d", i+1, response.Code, want)
		}
	}
}

func TestPublicRateLimitUsesTokenIdentityWhenValid(t *testing.T) {
	manager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:           []byte("integration-test-secret-with-32-bytes-minimum"),
		AccessTokenDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	aliceToken, err := manager.GenerateAccessToken(token.Claims{UserID: "user-alice"})
	if err != nil {
		t.Fatal(err)
	}
	app := goxis.New(goxis.WithAuthorizer(middleware.NewRBAC(manager)))
	if err := app.Group("/limited").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/", RateLimit: 1,
		Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, "ok") },
	}}); err != nil {
		t.Fatal(err)
	}
	for i, remoteAddr := range []string{"192.0.2.10:1000", "198.51.100.20:2000"} {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer "+aliceToken)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		want := http.StatusOK
		if i == 1 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("request %d status=%d want=%d", i+1, response.Code, want)
		}
	}
}
