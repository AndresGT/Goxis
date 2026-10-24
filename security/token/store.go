package token

import (
	"errors"
	"sync"
	"time"
)

type RefreshRecord struct {
	TokenID                     string // SHA-256 digest of the random jti, never the raw token.
	FamilyID, UserID, SessionID string
	ExpiresAt                   time.Time
}

type RotationStatus uint8

const (
	RotationRejected RotationStatus = iota
	RotationSucceeded
	RotationReuseDetected
)

// RefreshStore atomically consumes a refresh token and stores its replacement.
// ReuseDetected means the family must be revoked by the store.
type RefreshStore interface {
	Store(RefreshRecord) error
	Rotate(oldTokenID string, replacement RefreshRecord) (RotationStatus, error)
	RevokeUser(userID string) error
	RevokeSession(sessionID string) error
}

type memoryEntry struct {
	record   RefreshRecord
	active   bool
	consumed bool
}

// MemoryStore is intended for local development and single-process use only.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{entries: make(map[string]memoryEntry)} }
func (s *MemoryStore) Store(r RefreshRecord) error {
	if err := validRecord(r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[r.TokenID]; ok {
		return errors.New("token: duplicate refresh identifier")
	}
	s.entries[r.TokenID] = memoryEntry{record: r, active: true}
	return nil
}
func (s *MemoryStore) Rotate(old string, n RefreshRecord) (RotationStatus, error) {
	if err := validRecord(n); err != nil {
		return RotationRejected, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[old]
	if !ok || !e.active || !time.Now().Before(e.record.ExpiresAt) {
		if ok && e.consumed {
			for id, x := range s.entries {
				if x.record.FamilyID == e.record.FamilyID {
					x.active = false
					s.entries[id] = x
				}
			}
			return RotationReuseDetected, nil
		}
		return RotationRejected, nil
	}
	if e.record.FamilyID != n.FamilyID || e.record.UserID != n.UserID || e.record.SessionID != n.SessionID {
		return RotationRejected, nil
	}
	e.active = false
	e.consumed = true
	s.entries[old] = e
	s.entries[n.TokenID] = memoryEntry{record: n, active: true}
	return RotationSucceeded, nil
}
func (s *MemoryStore) RevokeUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if e.record.UserID == id {
			e.active = false
			s.entries[k] = e
		}
	}
	return nil
}
func (s *MemoryStore) RevokeSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if e.record.SessionID == id {
			e.active = false
			s.entries[k] = e
		}
	}
	return nil
}
func validRecord(r RefreshRecord) error {
	if r.TokenID == "" || r.FamilyID == "" || r.UserID == "" || r.SessionID == "" || r.ExpiresAt.IsZero() {
		return errors.New("token: incomplete refresh record")
	}
	return nil
}
