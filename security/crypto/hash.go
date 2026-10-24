// Package crypto provides password hashing, authenticated encryption and secure
// random generation. Password KDF implementations use golang.org/x/crypto.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type Algorithm string

const (
	AlgorithmBcrypt   Algorithm = "bcrypt"
	AlgorithmArgon2id Algorithm = "argon2id"
	AlgorithmScrypt   Algorithm = "scrypt"
	AlgorithmPBKDF2   Algorithm = "pbkdf2"
)

var (
	ErrInvalidHash          = errors.New("invalid password hash")
	ErrUnsupportedAlgorithm = errors.New("unsupported password hashing algorithm")
	ErrPasswordTooShort     = errors.New("password is too short")
	ErrPasswordTooLong      = errors.New("password is too long")
)

type Hasher interface {
	Hash(string) (string, error)
	Verify(string, string) (bool, error)
	NeedsUpgrade(string) bool
}

// HasherConfig contains settings for all supported password hash algorithms.
type HasherConfig struct {
	Algorithm                                              Algorithm
	PBKDF2Iterations, PBKDF2KeyLen, PBKDF2SaltLen          int
	BcryptCost                                             int
	Argon2Memory, Argon2Iterations                         uint32
	Argon2Parallelism                                      uint8
	Argon2KeyLength, Argon2SaltLength                      uint32
	ScryptN, ScryptR, ScryptP, ScryptKeyLen, ScryptSaltLen int
}

type PBKDF2Hasher struct{ iterations, keyLen, saltLen int }

func NewPBKDF2Hasher(cfg HasherConfig) (*PBKDF2Hasher, error) {
	if cfg.PBKDF2Iterations < 600000 {
		cfg.PBKDF2Iterations = 600000
	}
	if cfg.PBKDF2KeyLen < 32 {
		cfg.PBKDF2KeyLen = 32
	}
	if cfg.PBKDF2SaltLen < 16 {
		cfg.PBKDF2SaltLen = 16
	}
	if cfg.PBKDF2Iterations > 5000000 || cfg.PBKDF2KeyLen > 64 || cfg.PBKDF2SaltLen > 64 {
		return nil, errors.New("crypto: PBKDF2 parameters exceed safe bounds")
	}
	return &PBKDF2Hasher{cfg.PBKDF2Iterations, cfg.PBKDF2KeyLen, cfg.PBKDF2SaltLen}, nil
}

func (h *PBKDF2Hasher) Hash(password string) (string, error) {
	if len(password) > 1024 {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), salt, h.iterations, h.keyLen, sha256.New)
	return fmt.Sprintf("$pbkdf2-sha256$i=%d$%s$%s", h.iterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func (h *PBKDF2Hasher) Verify(password, encoded string) (bool, error) {
	if len(password) > 1024 {
		return false, ErrPasswordTooLong
	}
	p := strings.Split(encoded, "$")
	if len(p) != 5 || p[1] != "pbkdf2-sha256" || !strings.HasPrefix(p[2], "i=") {
		return false, ErrInvalidHash
	}
	iters, e := strconv.Atoi(strings.TrimPrefix(p[2], "i="))
	if e != nil || iters < 600000 || iters > 5000000 {
		return false, ErrInvalidHash
	}
	salt, e := base64.RawStdEncoding.DecodeString(p[3])
	if e != nil || len(salt) < 16 || len(salt) > 64 {
		return false, ErrInvalidHash
	}
	want, e := base64.RawStdEncoding.DecodeString(p[4])
	if e != nil || len(want) < 16 || len(want) > 64 {
		return false, ErrInvalidHash
	}
	got := pbkdf2.Key([]byte(password), salt, iters, len(want), sha256.New)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
func (h *PBKDF2Hasher) NeedsUpgrade(encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 5 {
		return true
	}
	i, e := strconv.Atoi(strings.TrimPrefix(p[2], "i="))
	return e != nil || i < h.iterations
}

// GoKitHasherConfig returns the same algorithm parameters used by GoKit's
// convenience functions. Argon2id is the default hashing algorithm.
func GoKitHasherConfig(algorithm Algorithm) (HasherConfig, error) {
	switch algorithm {
	case AlgorithmArgon2id:
		return HasherConfig{Algorithm: algorithm, Argon2Memory: 64 * 1024, Argon2Iterations: 3, Argon2Parallelism: 2, Argon2KeyLength: 32, Argon2SaltLength: 16}, nil
	case AlgorithmBcrypt:
		return HasherConfig{Algorithm: algorithm, BcryptCost: 12}, nil
	case AlgorithmScrypt:
		return HasherConfig{Algorithm: algorithm, ScryptN: 16384, ScryptR: 8, ScryptP: 1, ScryptKeyLen: 32, ScryptSaltLen: 16}, nil
	case AlgorithmPBKDF2:
		return HasherConfig{Algorithm: algorithm, PBKDF2Iterations: 600000, PBKDF2KeyLen: 32, PBKDF2SaltLen: 16}, nil
	default:
		return HasherConfig{}, ErrUnsupportedAlgorithm
	}
}

// NewHasher creates the requested hasher. An empty algorithm selects Argon2id,
// matching GoKit's default HashPassword behavior.
func NewHasher(cfg HasherConfig) (Hasher, error) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = AlgorithmArgon2id
	}
	switch cfg.Algorithm {
	case AlgorithmArgon2id:
		return NewArgon2Hasher(cfg)
	case AlgorithmBcrypt:
		return NewBcryptHasher(cfg)
	case AlgorithmScrypt:
		return NewScryptHasher(cfg)
	case AlgorithmPBKDF2:
		return NewPBKDF2Hasher(cfg)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func DetectAlgorithm(hash string) (Algorithm, error) {
	if !strings.HasPrefix(hash, "$") {
		return "", ErrInvalidHash
	}
	parts := strings.Split(hash, "$")
	if len(parts) < 3 {
		return "", ErrInvalidHash
	}
	switch parts[1] {
	case "2a", "2b", "2y":
		return AlgorithmBcrypt, nil
	case "argon2id":
		return AlgorithmArgon2id, nil
	case "scrypt":
		return AlgorithmScrypt, nil
	case "pbkdf2-sha256":
		return AlgorithmPBKDF2, nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}
