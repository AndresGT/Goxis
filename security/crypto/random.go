package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	ErrInvalidLength          = errors.New("length must be positive")
	ErrRandomGenerationFailed = errors.New("secure random generation failed")
	ErrInvalidPrefix          = errors.New("prefix must be alphanumeric")
)

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrInvalidLength
	}
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return nil, ErrRandomGenerationFailed
	}
	return b, nil
}
func RandomString(n int) (string, error) {
	if n <= 0 {
		return "", ErrInvalidLength
	}
	b := make([]byte, n)
	for i := range b {
		x, e := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if e != nil {
			return "", ErrRandomGenerationFailed
		}
		b[i] = charset[x.Int64()]
	}
	return string(b), nil
}
func RandomHex(n int) (string, error) {
	b, e := RandomBytes(n)
	if e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func GenerateUUID() (string, error) {
	b, e := RandomBytes(16)
	if e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func GenerateAPIKey(prefix string) (string, error) {
	if prefix == "" {
		prefix = "gx"
	}
	for _, c := range prefix {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return "", ErrInvalidPrefix
		}
	}
	s, e := RandomHex(32)
	return strings.ToLower(prefix) + "_" + s, e
}
func GenerateNumericCode(n int) (string, error) {
	if n <= 0 {
		return "", ErrInvalidLength
	}
	b := make([]byte, n)
	for i := range b {
		x, e := rand.Int(rand.Reader, big.NewInt(10))
		if e != nil {
			return "", ErrRandomGenerationFailed
		}
		b[i] = byte('0' + x.Int64())
	}
	return string(b), nil
}
func GenerateRandomBytes(n int) ([]byte, error)         { return RandomBytes(n) }
func GenerateRandomString(n int) (string, error)        { return RandomString(n) }
func GenerateSecureToken() (string, error)              { return RandomHex(32) }
func GenerateUUIDv4() (string, error)                   { return GenerateUUID() }
func GenerateAPIKeyWithPrefix(p string) (string, error) { return GenerateAPIKey(p) }
func GenerateOTP(n int) (string, error)                 { return GenerateNumericCode(n) }
