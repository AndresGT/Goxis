package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type ScryptHasher struct{ n, r, p, keyLen, saltLen int }

func NewScryptHasher(cfg HasherConfig) (*ScryptHasher, error) {
	n := cfg.ScryptN
	if n < 16384 || n&(n-1) != 0 {
		n = 16384
	}
	r := cfg.ScryptR
	if r < 8 {
		r = 8
	}
	p := cfg.ScryptP
	if p < 1 {
		p = 1
	}
	keyLen := cfg.ScryptKeyLen
	if keyLen < 32 {
		keyLen = 32
	}
	saltLen := cfg.ScryptSaltLen
	if saltLen < 16 {
		saltLen = 16
	}
	if n > 1<<17 || r > 16 || p > 4 || 128*n*r > 256*1024*1024 || keyLen > 64 || saltLen > 64 {
		return nil, errors.New("crypto: scrypt parameters exceed safe bounds")
	}
	return &ScryptHasher{n, r, p, keyLen, saltLen}, nil
}
func (h *ScryptHasher) Hash(password string) (string, error) {
	if len(password) > 1024 {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), salt, h.n, h.r, h.p, h.keyLen)
	if err != nil {
		return "", err
	}
	ln := 0
	for n := h.n; n > 1; n >>= 1 {
		ln++
	}
	return fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s", ln, h.r, h.p, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func (h *ScryptHasher) Verify(password, encoded string) (bool, error) {
	if len(password) > 1024 {
		return false, ErrPasswordTooLong
	}
	p := strings.Split(encoded, "$")
	if len(p) != 5 || p[1] != "scrypt" {
		return false, ErrInvalidHash
	}
	var ln, r, parallel int
	if _, err := fmt.Sscanf(p[2], "ln=%d,r=%d,p=%d", &ln, &r, &parallel); err != nil || ln < 14 || ln > 17 || r < 1 || r > 16 || parallel < 1 || parallel > 4 || 128*(1<<uint(ln))*r > 256*1024*1024 {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[3])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(p[4])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, ErrInvalidHash
	}
	got, err := scrypt.Key([]byte(password), salt, 1<<uint(ln), r, parallel, len(want))
	if err != nil {
		return false, ErrInvalidHash
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
func (h *ScryptHasher) NeedsUpgrade(encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 5 {
		return true
	}
	var ln, r, parallel int
	if _, err := fmt.Sscanf(p[2], "ln=%d,r=%d,p=%d", &ln, &r, &parallel); err != nil {
		return true
	}
	current := 0
	for n := h.n; n > 1; n >>= 1 {
		current++
	}
	return ln < current || r < h.r || parallel < h.p
}
