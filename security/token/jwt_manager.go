package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

// JWTConfig is the compact, single-secret configuration for applications that
// want the familiar GoKit-style setup. SecretKey must contain at least 32 bytes
// of high-entropy secret material. For split-key deployments use Config/New.
type JWTConfig struct {
	SecretKey            []byte
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	Issuer               string
	Audience             []string
	Store                RefreshStore
}

// JWTManager exposes the simple claims-oriented token API. The wire format is
// still encrypted JWE containing an EdDSA-signed JWT; it is not an unsigned or
// conventional visible-payload JWT.
type JWTManager struct{ manager *Manager }

func NewJWTManager(cfg JWTConfig) (*JWTManager, error) {
	if len(cfg.SecretKey) < 32 {
		return nil, errors.New("token: secret key must contain at least 32 bytes of high-entropy material")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "goxis"
	}
	if len(cfg.Audience) == 0 {
		cfg.Audience = []string{"goxis"}
	}
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	// Domain-separated derivation gives the convenience API one environment
	// secret while keeping signing and encryption keys cryptographically distinct.
	signSeed := deriveSecret("goxis/jwt/ed25519/v1", cfg.SecretKey)
	encKey := deriveSecret("goxis/jwt/aes-256-gcm/v1", cfg.SecretKey)
	private := ed25519.NewKeyFromSeed(signSeed[:])
	manager, err := New(Config{
		Issuer:          cfg.Issuer,
		Audience:        cfg.Audience,
		AccessTTL:       cfg.AccessTokenDuration,
		RefreshTTL:      cfg.RefreshTokenDuration,
		SigningKeyID:    "1",
		SigningKey:      private,
		EncryptionKeyID: "1",
		EncryptionKeys:  map[string][]byte{"1": encKey[:]},
		Store:           cfg.Store,
	})
	if err != nil {
		return nil, err
	}
	return &JWTManager{manager: manager}, nil
}

// GenerateAccessToken creates an access token from application claims.
func (m *JWTManager) GenerateAccessToken(claims Claims) (string, error) {
	return m.generate(claims, AccessToken)
}

// GenerateRefreshToken creates and records a one-time refresh token.
func (m *JWTManager) GenerateRefreshToken(claims Claims) (string, error) {
	return m.generate(claims, RefreshToken)
}

// GenerateTokenPair creates access and refresh tokens for one shared session.
func (m *JWTManager) GenerateTokenPair(claims Claims) (Pair, error) {
	if claims.SessionID == "" {
		id, err := randomID()
		if err != nil {
			return Pair{}, err
		}
		claims.SessionID = id
	}
	access, err := m.GenerateAccessToken(claims)
	if err != nil {
		return Pair{}, err
	}
	refresh, err := m.GenerateRefreshToken(claims)
	if err != nil {
		return Pair{}, err
	}
	return Pair{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int64(m.manager.cfg.AccessTTL.Seconds())}, nil
}

// ValidateToken decrypts, verifies and returns claims for either token type.
func (m *JWTManager) ValidateToken(raw string) (Claims, error) {
	if m == nil || m.manager == nil {
		return Claims{}, ErrInvalidToken
	}
	claims, err := m.manager.Validate(raw, AccessToken)
	if err == nil {
		return claims, nil
	}
	if errors.Is(err, ErrExpired) {
		return Claims{}, err
	}
	return m.manager.Validate(raw, RefreshToken)
}

// ValidateAccessToken validates only access tokens and satisfies the
// validator interface used by Goxis authorization middleware.
func (m *JWTManager) ValidateAccessToken(raw string) (Claims, error) {
	if m == nil || m.manager == nil {
		return Claims{}, ErrInvalidToken
	}
	return m.manager.Validate(raw, AccessToken)
}

// RefreshTokens validates and atomically rotates a refresh token.
func (m *JWTManager) RefreshTokens(raw string) (Pair, error) { return m.manager.Refresh(raw) }

func (m *JWTManager) RevokeUser(userID string) error       { return m.manager.RevokeUser(userID) }
func (m *JWTManager) RevokeSession(sessionID string) error { return m.manager.RevokeSession(sessionID) }

func (m *JWTManager) generate(input Claims, typ TokenType) (string, error) {
	userID := input.UserID
	if userID == "" {
		userID = input.Subject
	}
	if strings.TrimSpace(userID) == "" {
		return "", errors.New("token: user ID is required")
	}
	if input.SessionID == "" {
		id, err := randomID()
		if err != nil {
			return "", err
		}
		input.SessionID = id
	}
	// The simple API uses one refresh family per session. The lower-level
	// Manager supports separate family IDs when an application needs them.
	family := ""
	now := m.manager.cfg.Now().UTC()
	ttl := m.manager.cfg.AccessTTL
	if typ == RefreshToken {
		ttl = m.manager.cfg.RefreshTTL
	}
	claims, err := m.manager.claims(IssueOptions{UserID: userID, SessionID: input.SessionID, Roles: input.Roles, Permissions: input.Permissions}, now, ttl, typ, family)
	if err != nil {
		return "", err
	}
	claims.UserID, claims.Email, claims.CustomData = userID, input.Email, input.CustomData
	claims.Roles, claims.Permissions = input.Roles, input.Permissions
	raw, err := m.manager.seal(claims)
	if err != nil {
		return "", err
	}
	if typ == RefreshToken {
		if err := m.manager.cfg.Store.Store(recordFor(claims)); err != nil {
			return "", err
		}
	}
	return raw, nil
}

func deriveSecret(domain string, secret []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(secret)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
