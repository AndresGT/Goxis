package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryStorage struct {
	mu     sync.RWMutex
	events map[string]*Event
	closed bool
}

func NewMemoryStorage() *MemoryStorage { return &MemoryStorage{events: make(map[string]*Event)} }
func (s *MemoryStorage) Save(ctx context.Context, e *Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e == nil || e.ID == "" {
		return errors.New("event and ID are required")
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var cp Event
	if err = json.Unmarshal(b, &cp); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.events[e.ID] = &cp
	return nil
}
func (s *MemoryStorage) SaveBatch(ctx context.Context, events []*Event) error {
	for _, e := range events {
		if err := s.Save(ctx, e); err != nil {
			return err
		}
	}
	return nil
}
func (s *MemoryStorage) GetByID(ctx context.Context, id string) (*Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.events[id]
	if e == nil {
		return nil, errors.New("audit event not found")
	}
	b, _ := json.Marshal(e)
	var cp Event
	_ = json.Unmarshal(b, &cp)
	return &cp, nil
}
func (s *MemoryStorage) Query(ctx context.Context, f QueryFilter) ([]*Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Event, 0)
	for _, e := range s.events {
		if matches(e, f) {
			b, _ := json.Marshal(e)
			var cp Event
			_ = json.Unmarshal(b, &cp)
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if f.SortOrder == "asc" {
			return out[i].Timestamp.Before(out[j].Timestamp)
		}
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	start := f.Offset
	if start < 0 {
		start = 0
	}
	if start > len(out) {
		start = len(out)
	}
	end := len(out)
	if f.Limit > 0 && start+f.Limit < end {
		end = start + f.Limit
	}
	return out[start:end], nil
}
func (s *MemoryStorage) Count(ctx context.Context, f QueryFilter) (int64, error) {
	f.Offset = 0
	f.Limit = 0
	es, e := s.Query(ctx, f)
	return int64(len(es)), e
}
func (s *MemoryStorage) DeleteOlderThan(ctx context.Context, t time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, e := range s.events {
		if e.Timestamp.Before(t) {
			delete(s.events, id)
			n++
		}
	}
	return n, nil
}
func (s *MemoryStorage) Export(ctx context.Context, f QueryFilter, format ExportFormat, w io.Writer) error {
	events, err := s.Query(ctx, f)
	if err != nil {
		return err
	}
	switch format {
	case ExportFormatJSON:
		return json.NewEncoder(w).Encode(events)
	case ExportFormatNDJSON:
		enc := json.NewEncoder(w)
		for _, e := range events {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	case ExportFormatCSV:
		c := csv.NewWriter(w)
		if err = c.Write([]string{"id", "timestamp", "actor_id", "action", "resource_id", "status", "ip", "fingerprint"}); err != nil {
			return err
		}
		for _, e := range events {
			if err = c.Write([]string{e.ID, e.Timestamp.Format(time.RFC3339Nano), e.Actor.ID, e.Action.Type, e.Resource.ID, e.Result.Status, e.Context.IPAddress, e.DigitalFingerprint}); err != nil {
				return err
			}
		}
		c.Flush()
		return c.Error()
	default:
		return errors.New("unsupported audit export format")
	}
}
func (s *MemoryStorage) Close() error { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }
func matches(e *Event, f QueryFilter) bool {
	if !f.StartTime.IsZero() && e.Timestamp.Before(f.StartTime) || !f.EndTime.IsZero() && e.Timestamp.After(f.EndTime) {
		return false
	}
	if !contains(f.ActorIDs, e.Actor.ID) || !contains(f.ActionTypes, e.Action.Type) || !contains(f.ActionCategories, e.Action.Category) || !contains(f.ResourceTypes, e.Resource.Type) || !contains(f.ResourceIDs, e.Resource.ID) || !contains(f.Statuses, e.Result.Status) || !contains(f.IPAddresses, e.Context.IPAddress) {
		return false
	}
	if q := strings.ToLower(f.SearchQuery); q != "" {
		b, _ := json.Marshal(e)
		if !strings.Contains(strings.ToLower(string(b)), q) {
			return false
		}
	}
	return true
}
func contains(values []string, v string) bool {
	if len(values) == 0 {
		return true
	}
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}
