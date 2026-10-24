package crypto

import "sync"

var hasherMu sync.RWMutex
var defaultHasher Hasher = mustDefaultHasher()

func mustDefaultHasher() Hasher {
	cfg, _ := GoKitHasherConfig(AlgorithmArgon2id)
	h, err := NewArgon2Hasher(cfg)
	if err != nil {
		panic("crypto: initializing default Argon2id hasher: " + err.Error())
	}
	return h
}

// HashPassword creates an Argon2id hash using GoKit's default parameters.
func HashPassword(password string) (string, error) {
	hasherMu.RLock()
	h := defaultHasher
	hasherMu.RUnlock()
	return h.Hash(password)
}

// VerifyPassword detects the encoded algorithm and verifies using its stored
// parameters. Every legacy algorithm remains verifiable after default changes.
func VerifyPassword(password, storedHash string) (bool, error) {
	algorithm, err := DetectAlgorithm(storedHash)
	if err != nil {
		return false, err
	}
	cfg, err := GoKitHasherConfig(algorithm)
	if err != nil {
		return false, err
	}
	h, err := NewHasher(cfg)
	if err != nil {
		return false, err
	}
	return h.Verify(password, storedHash)
}

func NeedsUpgrade(storedHash string) bool {
	hasherMu.RLock()
	h := defaultHasher
	hasherMu.RUnlock()
	return h.NeedsUpgrade(storedHash)
}

func SetDefaultHasher(hasher Hasher) {
	if hasher == nil {
		return
	}
	hasherMu.Lock()
	defaultHasher = hasher
	hasherMu.Unlock()
}

func ConfigureDefaultHasher(cfg HasherConfig) error {
	h, err := NewHasher(cfg)
	if err != nil {
		return err
	}
	SetDefaultHasher(h)
	return nil
}

func HashWithArgon2id(password string) (string, error) {
	cfg, _ := GoKitHasherConfig(AlgorithmArgon2id)
	h, e := NewArgon2Hasher(cfg)
	if e != nil {
		return "", e
	}
	return h.Hash(password)
}
func HashWithBcrypt(password string) (string, error) {
	cfg, _ := GoKitHasherConfig(AlgorithmBcrypt)
	h, e := NewBcryptHasher(cfg)
	if e != nil {
		return "", e
	}
	return h.Hash(password)
}
func HashWithScrypt(password string) (string, error) {
	cfg, _ := GoKitHasherConfig(AlgorithmScrypt)
	h, e := NewScryptHasher(cfg)
	if e != nil {
		return "", e
	}
	return h.Hash(password)
}
func HashWithPBKDF2(password string) (string, error) {
	cfg, _ := GoKitHasherConfig(AlgorithmPBKDF2)
	h, e := NewPBKDF2Hasher(cfg)
	if e != nil {
		return "", e
	}
	return h.Hash(password)
}
