package main

import (
	"net/http"
	"time"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/middleware"
)

func RegisterDemoRoutes(api *goxis.Group) error {
	public := api.Group("/public")
	return public.RegisterRoutes([]goxis.Route{
		{Method: goxis.GET, Path: "/", Handler: publicRoute, RateLimit: 10, MaxConcurrent: 20, QueueLimit: 40},
		{Method: goxis.GET, Path: "/private", Handler: privateRoute, Protected: true, RateLimit: 5, MaxConcurrent: 4, QueueLimit: 12},
		{Method: goxis.GET, Path: "/admin", Handler: adminRoute, Protected: true, Roles: []string{"admin"}, RateLimit: 5, MaxConcurrent: 2, QueueLimit: 8},
		{Method: goxis.GET, Path: "/member", Handler: memberRoute, Protected: true, RateLimit: 5, MaxConcurrent: 4, QueueLimit: 12},
		{Method: goxis.POST, Path: "/ejemplo", Handler: publicRoute, RateLimit: 50, MaxConcurrent: 10, QueueLimit: 100},
		{Method: goxis.GET, Path: "/rate-limited", Handler: publicRoute, RateLimit: 2},
		{Method: goxis.GET, Path: "/queued", Handler: slowRoute, MaxConcurrent: 1, QueueLimit: 1},
	})
}

func slowRoute(ctx *goxis.Context) error {
	select {
	case <-time.After(3 * time.Second):
		return ctx.JSON(http.StatusOK, map[string]any{"route": "queued", "message": "Handler completado."})
	case <-ctx.Request.Context().Done():
		return ctx.Request.Context().Err()
	}
}

func publicRoute(ctx *goxis.Context) error {
	return ctx.JSON(http.StatusOK, map[string]any{
		"route":   "public",
		"message": "No requiere token.",
	})
}

func privateRoute(ctx *goxis.Context) error {
	claims := middleware.MustClaims(ctx)
	return ctx.JSON(http.StatusOK, map[string]any{
		"route":   "private",
		"message": "Requiere un access token válido, sin exigir un rol específico.",
		"user_id": claims.UserID,
		"roles":   claims.Roles,
	})
}

func adminRoute(ctx *goxis.Context) error {
	claims := middleware.MustClaims(ctx)
	return ctx.JSON(http.StatusOK, map[string]any{
		"route":               "group with role",
		"message":             "Acceso concedido al grupo admin.",
		"user_id":             claims.UserID,
		"roles":               claims.Roles,
		"required_permission": "read",
	})
}

func memberRoute(ctx *goxis.Context) error {
	claims := middleware.MustClaims(ctx)
	return ctx.JSON(http.StatusOK, map[string]any{
		"route":   "group without role",
		"message": "Grupo privado sin requisito de rol.",
		"user_id": claims.UserID,
		"roles":   claims.Roles,
	})
}
