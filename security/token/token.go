// Package token issues and validates interoperable encrypted access and refresh tokens.
// Tokens use nested JOSE compact serialization: an EdDSA signed JWS inside an
// A256GCM JWE. The implementation uses only Go's standard library.
package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AndresGT/Goxis/security"
)

var (
	ErrInvalidToken       = errors.New("token: invalid token")
	ErrExpired            = errors.New("token: expired token")
	ErrWrongType          = errors.New("token: unexpected token type")
	ErrSigningUnavailable = errors.New("token: signing key is not configured")
	ErrRefreshRejected    = errors.New("token: refresh token is invalid, expired, revoked, or already used")
)

type TokenType string

const (
	AccessToken      TokenType = "access"
	RefreshToken     TokenType = "refresh"
	TokenTypeAccess  TokenType = AccessToken
	TokenTypeRefresh TokenType = RefreshToken
)

// Claims are standard JWT claim names plus session and rotation identifiers.
type Claims struct {
	UserID      string         `json:"-"`
	Email       string         `json:"email,omitempty"`
	CustomData  map[string]any `json:"custom_data,omitempty"`
	Issuer      string         `json:"iss"`
	Subject     string         `json:"sub"`
	Audience    []string       `json:"aud,omitempty"`
	SessionID   string         `json:"sid"`
	TokenID     string         `json:"jti"`
	FamilyID    string         `json:"fid,omitempty"`
	TokenType   TokenType      `json:"token_use"`
	IssuedAt    int64          `json:"iat"`
	ExpiresAt   int64          `json:"exp"`
	Roles       []string       `json:"roles,omitempty"`
	Permissions []string       `json:"permissions,omitempty"`
}

type Config struct {
	Issuer           string
	Audience         []string
	Level            security.Level
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
	SigningKeyID     string
	SigningKey       ed25519.PrivateKey
	VerificationKeys map[string]ed25519.PublicKey
	EncryptionKeyID  string
	EncryptionKeys   map[string][]byte // AES-256 keys, exactly 32 bytes
	Store            RefreshStore      // Required to issue/rotate refresh tokens.
	Now              func() time.Time  // Optional clock hook.
}

type Manager struct{ cfg Config }

type IssueOptions struct {
	UserID      string
	SessionID   string // generated when omitted
	Email       string
	CustomData  map[string]any
	Roles       []string
	Permissions []string
}

type Pair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func New(cfg Config) (*Manager, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("token: issuer is required")
	}
	if len(cfg.Audience) == 0 {
		return nil, errors.New("token: at least one audience is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.AccessTTL <= 0 || cfg.RefreshTTL <= 0 {
		a, r := cfg.Level.Lifetimes()
		if cfg.AccessTTL <= 0 {
			cfg.AccessTTL = a
		}
		if cfg.RefreshTTL <= 0 {
			cfg.RefreshTTL = r
		}
	}
	if len(cfg.SigningKey) != 0 && len(cfg.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("token: signing key must be an Ed25519 private key")
	}
	if len(cfg.SigningKey) > 0 && cfg.SigningKeyID == "" {
		return nil, errors.New("token: signing key ID is required")
	}
	for id, key := range cfg.VerificationKeys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("token: invalid verification key %q", id)
		}
	}
	for id, key := range cfg.EncryptionKeys {
		if id == "" || len(key) != 32 {
			return nil, fmt.Errorf("token: encryption key %q must contain 32 bytes", id)
		}
	}
	if len(cfg.EncryptionKeys) == 0 {
		return nil, errors.New("token: at least one encryption key is required")
	}
	if cfg.EncryptionKeyID == "" || len(cfg.EncryptionKeys[cfg.EncryptionKeyID]) != 32 {
		return nil, errors.New("token: active encryption key ID is missing or invalid")
	}
	if len(cfg.SigningKey) > 0 {
		if cfg.VerificationKeys == nil {
			cfg.VerificationKeys = map[string]ed25519.PublicKey{}
		}
		cfg.VerificationKeys[cfg.SigningKeyID] = cfg.SigningKey.Public().(ed25519.PublicKey)
	}
	if len(cfg.VerificationKeys) == 0 {
		return nil, errors.New("token: at least one verification key is required")
	}
	return &Manager{cfg: cfg}, nil
}

func (m *Manager) Issue(opts IssueOptions) (Pair, error) {
	if opts.UserID == "" {
		return Pair{}, errors.New("token: user ID is required")
	}
	if m.cfg.Store == nil {
		return Pair{}, errors.New("token: refresh store is required to issue a token pair")
	}
	if opts.SessionID == "" {
		id, err := randomID()
		if err != nil {
			return Pair{}, err
		}
		opts.SessionID = id
	}
	family, err := randomID()
	if err != nil {
		return Pair{}, err
	}
	now := m.cfg.Now().UTC()
	accessClaims, err := m.claims(opts, now, m.cfg.AccessTTL, AccessToken, "")
	if err != nil {
		return Pair{}, err
	}
	refreshClaims, err := m.claims(opts, now, m.cfg.RefreshTTL, RefreshToken, family)
	if err != nil {
		return Pair{}, err
	}
	access, err := m.seal(accessClaims)
	if err != nil {
		return Pair{}, err
	}
	refresh, err := m.seal(refreshClaims)
	if err != nil {
		return Pair{}, err
	}
	if err := m.cfg.Store.Store(recordFor(refreshClaims)); err != nil {
		return Pair{}, fmt.Errorf("token: store refresh token: %w", err)
	}
	return Pair{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int64(m.cfg.AccessTTL.Seconds())}, nil
}

func (m *Manager) Refresh(raw string) (Pair, error) {
	c, err := m.Validate(raw, RefreshToken)
	if err != nil {
		return Pair{}, ErrRefreshRejected
	}
	if m.cfg.Store == nil {
		return Pair{}, errors.New("token: refresh store is required")
	}
	now := m.cfg.Now().UTC()
	newRefresh := c
	newID, err := randomID()
	if err != nil {
		return Pair{}, err
	}
	newRefresh.TokenID, newRefresh.IssuedAt, newRefresh.ExpiresAt = newID, now.Unix(), now.Add(m.cfg.RefreshTTL).Unix()
	newAccess := c
	newAccess.TokenID, newAccess.TokenType, newAccess.FamilyID = "", AccessToken, ""
	newAccess.IssuedAt, newAccess.ExpiresAt = now.Unix(), now.Add(m.cfg.AccessTTL).Unix()
	newAccess.TokenID, err = randomID()
	if err != nil {
		return Pair{}, err
	}
	access, err := m.seal(newAccess)
	if err != nil {
		return Pair{}, err
	}
	refresh, err := m.seal(newRefresh)
	if err != nil {
		return Pair{}, err
	}
	status, err := m.cfg.Store.Rotate(hashID(c.TokenID), recordFor(newRefresh))
	if err != nil {
		return Pair{}, fmt.Errorf("token: rotate refresh token: %w", err)
	}
	if status != RotationSucceeded {
		return Pair{}, ErrRefreshRejected
	}
	return Pair{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int64(m.cfg.AccessTTL.Seconds())}, nil
}

func (m *Manager) Validate(raw string, expected TokenType) (Claims, error) {
	var zero Claims
	if m == nil {
		return zero, ErrInvalidToken
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 5 {
		return zero, ErrInvalidToken
	}
	protected, err := decode(parts[0])
	if err != nil {
		return zero, ErrInvalidToken
	}
	var h map[string]string
	if json.Unmarshal(protected, &h) != nil || h["alg"] != "dir" || h["enc"] != "A256GCM" || h["cty"] != "JWT" {
		return zero, ErrInvalidToken
	}
	key := m.cfg.EncryptionKeys[h["kid"]]
	if len(key) != 32 {
		return zero, ErrInvalidToken
	}
	iv, e1 := decode(parts[2])
	ciphertext, e2 := decode(parts[3])
	tag, e3 := decode(parts[4])
	if e1 != nil || e2 != nil || e3 != nil || len(iv) != 12 || len(tag) != 16 {
		return zero, ErrInvalidToken
	}
	ciphertext = append(ciphertext, tag...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return zero, ErrInvalidToken
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return zero, ErrInvalidToken
	}
	plain, err := gcm.Open(nil, iv, ciphertext, []byte(parts[0]))
	if err != nil {
		return zero, ErrInvalidToken
	}
	return m.verifyJWS(string(plain), expected)
}

// ValidateAccessToken is the validator-only API used by HTTP authorization
// middleware. It does not require a signing key or refresh store.
func (m *Manager) ValidateAccessToken(raw string) (Claims, error) {
	return m.Validate(raw, AccessToken)
}

func (m *Manager) RevokeUser(userID string) error {
	if m.cfg.Store == nil {
		return errors.New("token: refresh store is required")
	}
	return m.cfg.Store.RevokeUser(userID)
}
func (m *Manager) RevokeSession(sessionID string) error {
	if m.cfg.Store == nil {
		return errors.New("token: refresh store is required")
	}
	return m.cfg.Store.RevokeSession(sessionID)
}

func (m *Manager) claims(o IssueOptions, now time.Time, ttl time.Duration, typ TokenType, family string) (Claims, error) {
	id, err := randomID()
	if err != nil {
		return Claims{}, err
	}
	return Claims{UserID: o.UserID, Email: o.Email, CustomData: o.CustomData, Issuer: m.cfg.Issuer, Subject: o.UserID, Audience: append([]string(nil), m.cfg.Audience...), SessionID: o.SessionID, TokenID: id, FamilyID: family, TokenType: typ, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), Roles: append([]string(nil), o.Roles...), Permissions: append([]string(nil), o.Permissions...)}, nil
}

func (m *Manager) seal(c Claims) (string, error) {
	if len(m.cfg.SigningKey) != ed25519.PrivateKeySize {
		return "", ErrSigningUnavailable
	}
	if len(m.cfg.EncryptionKeys[m.cfg.EncryptionKeyID]) != 32 {
		return "", errors.New("token: encryption key is not configured")
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": m.cfg.SigningKeyID})
	protected := b64(header)
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := protected + "." + b64(payload)
	sig := ed25519.Sign(m.cfg.SigningKey, []byte(input))
	jws := input + "." + b64(sig)
	jweHeader, _ := json.Marshal(map[string]string{"alg": "dir", "enc": "A256GCM", "cty": "JWT", "kid": m.cfg.EncryptionKeyID})
	p := b64(jweHeader)
	block, err := aes.NewCipher(m.cfg.EncryptionKeys[m.cfg.EncryptionKeyID])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(jws), []byte(p))
	split := len(sealed) - gcm.Overhead()
	return p + ".." + b64(nonce) + "." + b64(sealed[:split]) + "." + b64(sealed[split:]), nil
}

func (m *Manager) verifyJWS(raw string, expected TokenType) (Claims, error) {
	var c Claims
	p := strings.Split(raw, ".")
	if len(p) != 3 {
		return c, ErrInvalidToken
	}
	header, err := decode(p[0])
	if err != nil {
		return c, ErrInvalidToken
	}
	var h map[string]string
	if json.Unmarshal(header, &h) != nil || h["alg"] != "EdDSA" || h["typ"] != "JWT" {
		return c, ErrInvalidToken
	}
	pub := m.cfg.VerificationKeys[h["kid"]]
	sig, e1 := decode(p[2])
	payload, e2 := decode(p[1])
	if e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(p[0]+"."+p[1]), sig) {
		return c, ErrInvalidToken
	}
	if json.Unmarshal(payload, &c) != nil {
		return c, ErrInvalidToken
	}
	c.UserID = c.Subject
	now := m.cfg.Now().Unix()
	if c.Issuer != m.cfg.Issuer || c.Subject == "" || c.SessionID == "" || c.TokenID == "" || c.TokenType != expected || c.ExpiresAt <= c.IssuedAt {
		return Claims{}, ErrInvalidToken
	}
	if c.ExpiresAt <= now {
		return Claims{}, ErrExpired
	}
	if c.IssuedAt > now+60 {
		return Claims{}, ErrInvalidToken
	}
	if !containsAny(c.Audience, m.cfg.Audience) {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}
func containsAny(got, want []string) bool {
	for _, w := range want {
		for _, g := range got {
			if g == w {
				return true
			}
		}
	}
	return false
}
func randomID() (string, error) {
	// 128 bits is sufficient for opaque IDs and keeps tokens smaller than a
	// full 256-bit random identifier.
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return b64(b), nil
}
func b64(b []byte) string             { return base64.RawURLEncoding.EncodeToString(b) }
func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func recordFor(c Claims) RefreshRecord {
	familyID := c.FamilyID
	if familyID == "" {
		familyID = c.SessionID
	}
	return RefreshRecord{TokenID: hashID(c.TokenID), FamilyID: familyID, UserID: c.Subject, SessionID: c.SessionID, ExpiresAt: time.Unix(c.ExpiresAt, 0)}
}
func hashID(id string) string { x := sha256.Sum256([]byte(id)); return b64(x[:]) }
