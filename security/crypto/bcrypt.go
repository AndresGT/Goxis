package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type BcryptHasher struct{ cost int }

func NewBcryptHasher(cfg HasherConfig) (*BcryptHasher, error) {
	cost := cfg.BcryptCost
	if cost < bcrypt.MinCost {
		cost = 12
	}
	if cost > 16 {
		return nil, errors.New("crypto: bcrypt cost exceeds safe bound (16)")
	}
	return &BcryptHasher{cost}, nil
}
func preprocessBcryptPassword(password string) []byte {
	if len(password) <= 72 {
		return []byte(password)
	}
	sum := sha256.Sum256([]byte(password))
	return []byte(base64.StdEncoding.EncodeToString(sum[:]))
}
func (h *BcryptHasher) Hash(password string) (string, error) {
	if len(password) > 1024 {
		return "", ErrPasswordTooLong
	}
	b, err := bcrypt.GenerateFromPassword(preprocessBcryptPassword(password), h.cost)
	return string(b), err
}
func (h *BcryptHasher) Verify(password, encoded string) (bool, error) {
	if len(password) > 1024 {
		return false, ErrPasswordTooLong
	}
	cost, costErr := bcrypt.Cost([]byte(encoded))
	if costErr != nil || cost > 16 {
		return false, ErrInvalidHash
	}
	err := bcrypt.CompareHashAndPassword([]byte(encoded), preprocessBcryptPassword(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, ErrInvalidHash
	}
	return true, nil
}
func (h *BcryptHasher) NeedsUpgrade(encoded string) bool {
	cost, err := bcrypt.Cost([]byte(encoded))
	return err != nil || cost < h.cost
}
