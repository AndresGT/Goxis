package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"time"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/middleware"
	"github.com/AndresGT/Goxis/security/token"
)

type DemoTokens struct {
	Admin  string
	Viewer string
}

func InitRoutes() (*goxis.App, DemoTokens, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) < 32 {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return nil, DemoTokens{}, err
		}
		secret = []byte(base64.RawURLEncoding.EncodeToString(bytes))
		log.Println("JWT_SECRET no configurado: usando una clave efímera solo para este demo")
	}

	jwtManager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:            secret,
		AccessTokenDuration:  30 * time.Minute,
		RefreshTokenDuration: 24 * time.Hour,
	})
	if err != nil {
		return nil, DemoTokens{}, err
	}

	authorizer := middleware.NewRBAC(jwtManager,
		middleware.Role{Name: "viewer", Permissions: []string{"read"}},
		middleware.Role{Name: "admin", Permissions: []string{"*"}},
	)
	app := goxis.New(goxis.WithAuthorizer(authorizer))

	// CORS controls browser response access. No OriginGuard is installed here,
	// so the public example endpoint can also be opened in the address bar.
	middleware.CORS(middleware.CORSConfig{
		AllowedOrigins: []string{"http://localhost:3030", "http://localhost:8080"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "Idempotency-Key"},
	})(app)

	api := app.Group("/api")
	if err := RegisterDemoRoutes(api); err != nil {
		return nil, DemoTokens{}, err
	}

	adminPair, err := jwtManager.GenerateTokenPair(token.Claims{UserID: "demo-admin", Roles: []string{"admin"}})
	if err != nil {
		return nil, DemoTokens{}, err
	}
	viewerPair, err := jwtManager.GenerateTokenPair(token.Claims{UserID: "demo-viewer", Roles: []string{"viewer"}})
	if err != nil {
		return nil, DemoTokens{}, err
	}
	return app, DemoTokens{Admin: adminPair.AccessToken, Viewer: viewerPair.AccessToken}, nil
}
