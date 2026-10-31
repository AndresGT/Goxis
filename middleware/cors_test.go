package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/middleware"
)

func TestOriginGuardIsOptIn(t *testing.T) {
	newApp := func() *goxis.App {
		app := goxis.New()
		if err := app.Group("/").RegisterRoutes([]goxis.Route{{
			Method: goxis.GET, Path: "/resource",
			Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, "ok") },
		}}); err != nil {
			t.Fatal(err)
		}
		return app
	}

	plain := newApp()
	for _, origin := range []string{"", "https://untrusted.example"} {
		request := httptest.NewRequest(http.MethodGet, "/resource", nil)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		response := httptest.NewRecorder()
		plain.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("without OriginGuard origin=%q status=%d", origin, response.Code)
		}
	}

	guarded := newApp()
	middleware.OriginGuard("https://frontend.example")(guarded)
	for _, origin := range []string{"", "https://untrusted.example"} {
		request := httptest.NewRequest(http.MethodGet, "/resource", nil)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		response := httptest.NewRecorder()
		guarded.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("with OriginGuard origin=%q status=%d want=%d", origin, response.Code, http.StatusForbidden)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/resource", nil)
	request.Header.Set("Origin", "https://frontend.example")
	response := httptest.NewRecorder()
	guarded.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("allowed origin status=%d", response.Code)
	}
}

func TestCORSAllowsCredentialedRequestsOnlyForConfiguredOrigin(t *testing.T) {
	app := goxis.New()
	if err := app.Group("/").RegisterRoutes([]goxis.Route{{
		Method: goxis.GET, Path: "/resource",
		Handler: func(ctx *goxis.Context) error { return ctx.Text(http.StatusOK, "ok") },
	}}); err != nil {
		t.Fatal(err)
	}
	middleware.CORS(middleware.CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3030"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	})(app)

	preflight := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	preflight.Header.Set("Origin", "http://localhost:3030")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	preflight.Header.Set("Access-Control-Request-Headers", "Content-Type")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, preflight)
	if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Credentials") != "true" || response.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3030" {
		t.Fatalf("credentialed preflight status=%d headers=%v", response.Code, response.Header())
	}

	request := httptest.NewRequest(http.MethodGet, "/resource", nil)
	request.Header.Set("Origin", "http://untrusted.example")
	response = httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("regular disallowed-origin request should reach route without CORS grant: status=%d headers=%v", response.Code, response.Header())
	}
}
