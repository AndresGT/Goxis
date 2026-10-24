package security

import "errors"

var (
	ErrInvalidHash               = errors.New("invalid password hash")
	ErrIncompatibleVersion       = errors.New("incompatible security version")
	ErrInvalidCiphertext         = errors.New("invalid ciphertext")
	ErrInvalidKeyLength          = errors.New("invalid key length")
	ErrAuthenticationFailed      = errors.New("authentication failed")
	ErrPermissionDenied          = errors.New("permission denied")
	ErrInsufficientSecurityLevel = errors.New("insufficient security level")
	ErrTokenInvalid              = errors.New("invalid or expired token")
	ErrTokenRevoked              = errors.New("token revoked")
	ErrSessionExpired            = errors.New("session expired")
	ErrRateLimitExceeded         = errors.New("rate limit exceeded")
	ErrAccountLocked             = errors.New("account locked")
	ErrIPBlocked                 = errors.New("IP blocked")
	ErrInvalidInput              = errors.New("invalid input")
	ErrWeakPassword              = errors.New("password does not meet security requirements")
	ErrOperationNotAllowed       = errors.New("operation not allowed")
	ErrPasswordChangeRequired    = errors.New("password change required")
)
