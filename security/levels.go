// Package security contains shared security policies used by Goxis modules.
package security

import "time"

// Level selects the default lifetime of access and refresh tokens.
type Level uint8

const (
	Default Level = iota
	Low
	Medium
	High
	Critical
	LevelDefault  = Default
	LevelLow      = Low
	LevelMedium   = Medium
	LevelHigh     = High
	LevelCritical = Critical
)

// SecurityDefaults contains recommended starting policies for authentication.
type SecurityDefaults struct {
	BcryptCost                                int
	AccessTokenDuration, RefreshTokenDuration time.Duration
	MaxLoginAttempts                          int
	LockoutDuration                           time.Duration
	PasswordResetMaxPerHour                   int
	MaxConcurrentSessions                     int
	SessionTimeout, IdleTimeout               time.Duration
	Require2FA                                bool
}

func (l Level) GetDefaults() SecurityDefaults {
	a, r := l.Lifetimes()
	switch l {
	case Low:
		return SecurityDefaults{BcryptCost: 10, AccessTokenDuration: a, RefreshTokenDuration: r, MaxLoginAttempts: 10, LockoutDuration: 5 * time.Minute, PasswordResetMaxPerHour: 5, MaxConcurrentSessions: 5, SessionTimeout: 7 * 24 * time.Hour, IdleTimeout: 24 * time.Hour}
	case High:
		return SecurityDefaults{BcryptCost: 14, AccessTokenDuration: a, RefreshTokenDuration: r, MaxLoginAttempts: 3, LockoutDuration: time.Hour, PasswordResetMaxPerHour: 2, MaxConcurrentSessions: 2, SessionTimeout: 8 * time.Hour, IdleTimeout: 15 * time.Minute, Require2FA: true}
	case Critical:
		return SecurityDefaults{BcryptCost: 15, AccessTokenDuration: a, RefreshTokenDuration: r, MaxLoginAttempts: 3, LockoutDuration: 24 * time.Hour, PasswordResetMaxPerHour: 1, MaxConcurrentSessions: 1, SessionTimeout: 2 * time.Hour, IdleTimeout: 5 * time.Minute, Require2FA: true}
	default:
		return SecurityDefaults{BcryptCost: 12, AccessTokenDuration: a, RefreshTokenDuration: r, MaxLoginAttempts: 5, LockoutDuration: 15 * time.Minute, PasswordResetMaxPerHour: 3, MaxConcurrentSessions: 3, SessionTimeout: 24 * time.Hour, IdleTimeout: 30 * time.Minute}
	}
}

func (l Level) String() string {
	switch l {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "DEFAULT"
	}
}
func (l Level) IsValid() bool { return l <= Critical }

// Lifetimes returns the default access and refresh lifetimes for a level.
func (l Level) Lifetimes() (access, refresh time.Duration) {
	switch l {
	case Low:
		return 24 * time.Hour, 30 * 24 * time.Hour
	case High:
		return 15 * time.Minute, 24 * time.Hour
	case Critical:
		return 5 * time.Minute, 12 * time.Hour
	default: // Default and Medium
		return time.Hour, 7 * 24 * time.Hour
	}
}
