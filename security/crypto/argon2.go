package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	memory, iterations    uint32
	parallelism           uint8
	keyLength, saltLength uint32
}

func NewArgon2Hasher(cfg HasherConfig) (*Argon2Hasher, error) {
	if cfg.Argon2Memory < 64*1024 {
		cfg.Argon2Memory = 64 * 1024
	}
	if cfg.Argon2Iterations < 3 {
		cfg.Argon2Iterations = 3
	}
	if cfg.Argon2Parallelism < 1 {
		cfg.Argon2Parallelism = 4
	}
	if cfg.Argon2KeyLength < 32 {
		cfg.Argon2KeyLength = 32
	}
	if cfg.Argon2SaltLength < 16 {
		cfg.Argon2SaltLength = 16
	}
	if cfg.Argon2Memory > 128*1024 || cfg.Argon2Iterations > 6 || cfg.Argon2Parallelism > 8 || uint64(cfg.Argon2Memory)*uint64(cfg.Argon2Iterations) > 512*1024 || cfg.Argon2KeyLength > 64 || cfg.Argon2SaltLength > 64 {
		return nil, errors.New("crypto: Argon2id parameters exceed safe bounds")
	}
	return &Argon2Hasher{cfg.Argon2Memory, cfg.Argon2Iterations, cfg.Argon2Parallelism, cfg.Argon2KeyLength, cfg.Argon2SaltLength}, nil
}
func (h *Argon2Hasher) Hash(password string) (string, error) {
	if len(password) > 1024 {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, h.saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", h.memory, h.iterations, h.parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func (h *Argon2Hasher) Verify(password, encoded string) (bool, error) {
	if len(password) > 1024 {
		return false, ErrPasswordTooLong
	}
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" || p[2] != "v=19" {
		return false, ErrInvalidHash
	}
	var m, t uint64
	var parallel uint64
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &m, &t, &parallel); err != nil || m < 8*parallel || m > 128*1024 || t < 1 || t > 6 || parallel < 1 || parallel > 8 || m*t > 512*1024 {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(p[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, ErrInvalidHash
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(parallel), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
func (h *Argon2Hasher) NeedsUpgrade(encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 {
		return true
	}
	fields := strings.Split(p[3], ",")
	if len(fields) != 3 {
		return true
	}
	m, e1 := strconv.ParseUint(strings.TrimPrefix(fields[0], "m="), 10, 32)
	t, e2 := strconv.ParseUint(strings.TrimPrefix(fields[1], "t="), 10, 32)
	par, e3 := strconv.ParseUint(strings.TrimPrefix(fields[2], "p="), 10, 8)
	return e1 != nil || e2 != nil || e3 != nil || uint32(m) < h.memory || uint32(t) < h.iterations || uint8(par) < h.parallelism
}
