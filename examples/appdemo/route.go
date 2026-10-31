package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/middleware"
	goxiscrypto "github.com/AndresGT/Goxis/security/crypto"
	"github.com/AndresGT/Goxis/security/token"
)

type DemoTokens struct {
	Admin  string
	Viewer string
}

func InitRoutes() (*goxis.App, DemoTokens, error) {
	secret, err := loadDemoSecret()
	if err != nil {
		return nil, DemoTokens{}, err
	}

	jwtManager, err := token.NewJWTManager(token.JWTConfig{
		SecretKey:            secret,
		AccessTokenDuration:  24 * time.Hour,
		RefreshTokenDuration: 24 * time.Hour,
	})
	if err != nil {
		return nil, DemoTokens{}, err
	}
	adminPasswordHash, err := goxiscrypto.HashPassword("admin")
	if err != nil {
		return nil, DemoTokens{}, err
	}

	authorizer := middleware.NewRBAC(jwtManager,
		middleware.Role{Name: "viewer", Permissions: []string{"read"}},
		middleware.Role{Name: "admin", Permissions: []string{"*"}},
	)
	app := goxis.New(
		goxis.WithAuthorizer(authorizer),
		goxis.WithAdminPanel(goxis.AdminPanelConfig{
			MaxLogEntries: 500, AdminUsername: "admin", AdminPasswordHash: adminPasswordHash,
			TokenManager: jwtManager, SessionTTL: 24 * time.Hour,
			SecureCookie: os.Getenv("GOXIS_ADMIN_SECURE_COOKIE") == "true",
			LogFilePath:  filepath.Join("logs", "goxis-appdemo.log"), MaxLogFileBytes: 10 << 20, MaxLogFiles: 5,
		}),
	)

	// CORS controls browser response access. No OriginGuard is installed here,
	// so the public example endpoint can also be opened in the address bar.
	middleware.CORS(middleware.CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3030", "http://localhost:8080", "http://127.0.0.1:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "Idempotency-Key"},
		ExposedHeaders:   []string{goxis.RequestIDHeader},
		AllowCredentials: true,
	})(app)

	api := app.Group("/api")
	if err := RegisterDemoRoutes(api); err != nil {
		_ = app.Close()
		return nil, DemoTokens{}, err
	}

	adminPair, err := jwtManager.GenerateTokenPair(token.Claims{UserID: "demo-admin", Roles: []string{"admin"}})
	if err != nil {
		_ = app.Close()
		return nil, DemoTokens{}, err
	}
	viewerPair, err := jwtManager.GenerateTokenPair(token.Claims{UserID: "demo-viewer", Roles: []string{"viewer"}})
	if err != nil {
		_ = app.Close()
		return nil, DemoTokens{}, err
	}
	return app, DemoTokens{Admin: adminPair.AccessToken, Viewer: viewerPair.AccessToken}, nil
}

// loadDemoSecret keeps the local demo's admin cookie valid across restarts.
// Real applications should provide a stable, high-entropy JWT_SECRET instead.
func loadDemoSecret() ([]byte, error) {
	if secret, exists := os.LookupEnv("JWT_SECRET"); exists {
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT_SECRET debe tener al menos 32 bytes")
		}
		return []byte(secret), nil
	}
	path := filepath.Join("logs", "appdemo-jwt.key")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	secret, err := os.ReadFile(path)
	if err == nil {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(secret))
		if decodeErr != nil || len(decoded) < 32 {
			return nil, fmt.Errorf("invalid demo key at %s", path)
		}
		return []byte(string(secret)), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(random))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return loadDemoSecret()
	}
	if err != nil {
		return nil, err
	}
	if _, err = file.Write(encoded); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	log.Printf("Clave local del demo guardada en %s", path)
	return encoded, nil
}
