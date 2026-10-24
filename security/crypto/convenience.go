package crypto

import (
	"errors"
	"sync"
)

var globalCipherMu sync.RWMutex
var globalCipher *AESEncrypter
var ErrEncryptionKeyNotConfigured = errors.New("encryption key is not configured")

func SetEncryptionKey(key []byte) error {
	enc, err := NewAESEncrypter(key)
	if err != nil {
		return err
	}
	globalCipherMu.Lock()
	globalCipher = enc
	globalCipherMu.Unlock()
	return nil
}
func configuredCipher() (*AESEncrypter, error) {
	globalCipherMu.RLock()
	defer globalCipherMu.RUnlock()
	if globalCipher == nil {
		return nil, ErrEncryptionKeyNotConfigured
	}
	return globalCipher, nil
}
func EncryptString(s string) (string, error) {
	e, err := configuredCipher()
	if err != nil {
		return "", err
	}
	return e.EncryptString(s)
}
func DecryptString(s string) (string, error) {
	e, err := configuredCipher()
	if err != nil {
		return "", err
	}
	return e.DecryptString(s)
}
func EncryptBytes(b []byte) (string, error) {
	e, err := configuredCipher()
	if err != nil {
		return "", err
	}
	return e.Encrypt(b)
}
func DecryptBytes(s string) ([]byte, error) {
	e, err := configuredCipher()
	if err != nil {
		return nil, err
	}
	return e.Decrypt(s)
}
