package middleware

import (
	"strings"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/security/token"
)

const (
	UserIDContextKey = "goxis.user_id"
	ClaimsContextKey = "goxis.user_claims"
)

// AccessTokenValidator verifies access tokens without requiring the caller to
// have token signing capability. Both token.Manager and token.JWTManager
// implement it.
type AccessTokenValidator interface {
	ValidateAccessToken(raw string) (token.Claims, error)
}

// RequireAuth validates the bearer token and stores its Claims in the request
// context. On failure it returns a Goxis sentinel; the app serializes the error
// response. Refresh tokens are never accepted on protected API routes.
func RequireAuth(manager AccessTokenValidator) goxis.Middleware {
	return func(next goxis.Handler) goxis.Handler {
		return func(ctx *goxis.Context) error {
			if manager == nil {
				return goxis.ErrAccessControlUnavailable
			}
			if claims, ok := ClaimsFromContext(ctx); ok {
				ctx.SetAuthenticatedIdentity(claims.UserID)
				return next(ctx)
			}
			parts := strings.Fields(ctx.Request.Header.Get("Authorization"))
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
				return goxis.ErrUnauthenticated
			}
			claims, err := manager.ValidateAccessToken(parts[1])
			if err != nil {
				return goxis.ErrUnauthenticated
			}
			setClaims(ctx, claims)
			ctx.SetAuthenticatedIdentity(claims.UserID)
			return next(ctx)
		}
	}
}

// ClaimsFromContext retrieves claims previously attached by RequireAuth.
func ClaimsFromContext(ctx *goxis.Context) (token.Claims, bool) {
	if ctx == nil {
		return token.Claims{}, false
	}
	value, ok := ctx.Get(ClaimsContextKey)
	if !ok {
		return token.Claims{}, false
	}
	claims, ok := value.(token.Claims)
	return claims, ok
}

// MustClaims returns the claims attached by successful authentication
// middleware. Protected handlers can use it without repeating auth checks.
// It panics only when called outside an authenticated request flow, which
// indicates a route or middleware configuration bug.
func MustClaims(ctx *goxis.Context) token.Claims {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		panic("middleware: claims are unavailable; ensure this handler is behind a protected route with an Authorizer")
	}
	return claims
}
