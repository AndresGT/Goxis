package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidKeyLength  = errors.New("AES-256 requires a 32-byte key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

type Encrypter interface {
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
	EncryptString(string) (string, error)
	DecryptString(string) (string, error)
}
type AESEncrypter struct{ gcm cipher.AEAD }

func NewAESEncrypter(key []byte) (*AESEncrypter, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return &AESEncrypter{gcm: g}, nil
}
func (e *AESEncrypter) Encrypt(p []byte) (string, error) {
	n := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return "", ErrEncryptionFailed
	}
	raw := e.gcm.Seal(n, n, p, nil)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func (e *AESEncrypter) Decrypt(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < e.gcm.NonceSize()+e.gcm.Overhead() {
		return nil, ErrInvalidCiphertext
	}
	n := raw[:e.gcm.NonceSize()]
	p, err := e.gcm.Open(nil, n, raw[e.gcm.NonceSize():], nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return p, nil
}
func (e *AESEncrypter) EncryptString(s string) (string, error) { return e.Encrypt([]byte(s)) }
func (e *AESEncrypter) DecryptString(s string) (string, error) {
	p, err := e.Decrypt(s)
	return string(p), err
}
func GenerateEncryptionKey() ([]byte, error) { return RandomBytes(32) }
func GenerateEncryptionKeyBase64() (string, error) {
	b, e := GenerateEncryptionKey()
	if e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
func EncryptWithKey(p string, key []byte) (string, error) {
	e, err := NewAESEncrypter(key)
	if err != nil {
		return "", err
	}
	return e.EncryptString(p)
}
func DecryptWithKey(c string, key []byte) (string, error) {
	e, err := NewAESEncrypter(key)
	if err != nil {
		return "", err
	}
	return e.DecryptString(c)
}
