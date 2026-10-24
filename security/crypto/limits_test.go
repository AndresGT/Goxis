package crypto

import "testing"

func TestRejectsExcessiveKDFParameters(t *testing.T) {
	if _, err := NewBcryptHasher(HasherConfig{BcryptCost: 17}); err == nil {
		t.Fatal("expected bcrypt cost rejection")
	}
	if _, err := NewScryptHasher(HasherConfig{ScryptN: 1 << 18, ScryptR: 8, ScryptP: 1}); err == nil {
		t.Fatal("expected scrypt memory bound rejection")
	}
	if _, err := NewArgon2Hasher(HasherConfig{Argon2Memory: 256 * 1024, Argon2Iterations: 3, Argon2Parallelism: 2}); err == nil {
		t.Fatal("expected Argon2 memory bound rejection")
	}
}

func TestVerifyRejectsExcessiveStoredParametersBeforeKDF(t *testing.T) {
	argon, _ := NewArgon2Hasher(HasherConfig{})
	if _, err := argon.Verify("x", "$argon2id$v=19$m=262144,t=3,p=2$c2FsdHNhbHQ$YWJjZGVmZ2hpamtsbW5vcA"); err != ErrInvalidHash {
		t.Fatalf("argon2 err=%v", err)
	}
	scrypt, _ := NewScryptHasher(HasherConfig{})
	if _, err := scrypt.Verify("x", "$scrypt$ln=18,r=8,p=1$c2FsdHNhbHQ$YWJjZGVmZ2hpamtsbW5vcA"); err != ErrInvalidHash {
		t.Fatalf("scrypt err=%v", err)
	}
	tooLong := make([]byte, 1025)
	if _, err := argon.Verify(string(tooLong), "malformed"); err != ErrPasswordTooLong {
		t.Fatalf("password length err=%v", err)
	}
}
