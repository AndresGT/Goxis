// Package audit records security and business events with pluggable storage.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/AndresGT/Goxis/security/crypto"
)

var ErrClosed = errors.New("auditor is closed")

type Event struct {
	ID                 string         `json:"id"`
	Timestamp          time.Time      `json:"timestamp"`
	Actor              ActorInfo      `json:"actor"`
	Action             ActionInfo     `json:"action"`
	Resource           ResourceInfo   `json:"resource"`
	Result             ResultInfo     `json:"result"`
	Context            ContextInfo    `json:"context"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	RiskScore          float64        `json:"risk_score,omitempty"`
	DigitalFingerprint string         `json:"digital_fingerprint"`
}
type ActorInfo struct {
	ID        string `json:"id,omitempty"`
	Email     string `json:"email,omitempty"`
	Username  string `json:"username,omitempty"`
	Role      string `json:"role,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Type      string `json:"type,omitempty"`
}
type ActionInfo struct {
	Type        string `json:"type"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
}
type ResourceInfo struct {
	Type       string `json:"type,omitempty"`
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Collection string `json:"collection,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
}
type ResultInfo struct {
	Status       string `json:"status"`
	StatusCode   int    `json:"status_code,omitempty"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
	Duration     int64  `json:"duration_ms,omitempty"`
	ChangesCount int    `json:"changes_count,omitempty"`
}
type ContextInfo struct {
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Referer   string `json:"referer,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
}
type QueryFilter struct {
	ActorIDs, ActionTypes, ActionCategories, ResourceTypes, ResourceIDs, Statuses, IPAddresses []string
	StartTime, EndTime                                                                         time.Time
	SearchQuery                                                                                string
	Limit, Offset                                                                              int
	SortBy, SortOrder                                                                          string
}
type ExportFormat string

const (
	ExportFormatJSON   ExportFormat = "json"
	ExportFormatCSV    ExportFormat = "csv"
	ExportFormatNDJSON ExportFormat = "ndjson"
)

type Storage interface {
	Save(context.Context, *Event) error
	SaveBatch(context.Context, []*Event) error
	GetByID(context.Context, string) (*Event, error)
	Query(context.Context, QueryFilter) ([]*Event, error)
	Count(context.Context, QueryFilter) (int64, error)
	DeleteOlderThan(context.Context, time.Time) (int64, error)
	Export(context.Context, QueryFilter, ExportFormat, io.Writer) error
	Close() error
}
type Config struct {
	Storage Storage
}
type Auditor struct {
	storage Storage
	mu      sync.RWMutex
	closed  bool
}

var defaultMu sync.RWMutex
var defaultAuditor *Auditor

// Init replaces the package default auditor using the provided configuration.
func Init(cfg Config) error {
	a, err := NewAuditor(cfg)
	if err != nil {
		return err
	}
	defaultMu.Lock()
	old := defaultAuditor
	defaultAuditor = a
	defaultMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// GetDefault returns the configured package default auditor, or nil.
func GetDefault() *Auditor { defaultMu.RLock(); defer defaultMu.RUnlock(); return defaultAuditor }

// SetDefault sets the package default auditor. Pass nil to clear it.
func SetDefault(a *Auditor) { defaultMu.Lock(); defaultAuditor = a; defaultMu.Unlock() }

// RecordQuick records through the default auditor.
func RecordQuick(e *Event) error {
	a := GetDefault()
	if a == nil {
		return errors.New("default auditor is not configured")
	}
	return a.Record(e)
}

// QueryQuick queries through the default auditor.
func QueryQuick(ctx context.Context, f QueryFilter) ([]*Event, error) {
	a := GetDefault()
	if a == nil {
		return nil, errors.New("default auditor is not configured")
	}
	return a.Query(ctx, f)
}

// ExportQuick exports through the default auditor.
func ExportQuick(ctx context.Context, f QueryFilter, format ExportFormat, w io.Writer) error {
	a := GetDefault()
	if a == nil {
		return errors.New("default auditor is not configured")
	}
	return a.Export(ctx, f, format, w)
}

func NewAuditor(cfg Config) (*Auditor, error) {
	s := cfg.Storage
	if s == nil {
		s = NewMemoryStorage()
	}
	return &Auditor{storage: s}, nil
}
func (a *Auditor) Record(e *Event) error {
	if e == nil {
		return errors.New("audit event is nil")
	}
	a.mu.RLock()
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if e.ID == "" {
		id, err := crypto.GenerateUUID()
		if err != nil {
			return err
		}
		e.ID = id
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.DigitalFingerprint == "" {
		copy := *e
		copy.DigitalFingerprint = ""
		b, err := json.Marshal(copy)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		e.DigitalFingerprint = hex.EncodeToString(sum[:])
	}
	return a.storage.Save(context.Background(), e)
}
func (a *Auditor) Query(ctx context.Context, f QueryFilter) ([]*Event, error) {
	return a.storage.Query(ctx, f)
}
func (a *Auditor) GetByID(ctx context.Context, id string) (*Event, error) {
	return a.storage.GetByID(ctx, id)
}
func (a *Auditor) Count(ctx context.Context, f QueryFilter) (int64, error) {
	return a.storage.Count(ctx, f)
}
func (a *Auditor) Export(ctx context.Context, f QueryFilter, format ExportFormat, w io.Writer) error {
	return a.storage.Export(ctx, f, format, w)
}
func (a *Auditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.storage.Close()
}
