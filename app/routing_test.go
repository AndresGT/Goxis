package goxis_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
