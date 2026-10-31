package goxis

import (
	"context"
	"sync"
	"time"
)

const maxRouteQueueCapacity = 65536

// requestQueue places a hard admission bound around one route while limiting
// the number of handlers running concurrently.
type requestQueue struct {
	admitted chan struct{}
	running  chan struct{}
	mu       sync.RWMutex
	rejected uint64
	canceled uint64
	failures []queueFailure
}

type queueAdmission uint8

const (
	queueAdmitted queueAdmission = iota
	queueRejected
	queueCanceled
)

type queueFailure struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	Route     string    `json:"route"`
	Group     string    `json:"group"`
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	ClientIP  string    `json:"client_ip"`
	RequestID string    `json:"request_id"`
}

type queueRouteStatus struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Group         string `json:"group"`
	MaxConcurrent int    `json:"max_concurrent"`
	QueueLimit    int    `json:"queue_limit"`
	Running       int    `json:"running"`
	Waiting       int    `json:"waiting"`
	Rejected      uint64 `json:"rejected"`
	Canceled      uint64 `json:"canceled"`
}

type queuePanelSnapshot struct {
	Routes   []queueRouteStatus `json:"routes"`
	Failures []queueFailure     `json:"failures"`
	Running  int                `json:"running"`
	Waiting  int                `json:"waiting"`
	Rejected uint64             `json:"rejected"`
	Canceled uint64             `json:"canceled"`
}

func newRequestQueue(concurrency, waiting int) *requestQueue {
	if concurrency <= 0 {
		return nil
	}
	return &requestQueue{admitted: make(chan struct{}, concurrency+waiting), running: make(chan struct{}, concurrency)}
}

func (q *requestQueue) acquire(ctx context.Context, onChange func()) (func(), queueAdmission) {
	select {
	case q.admitted <- struct{}{}:
	default:
		q.mu.Lock()
		q.rejected++
		q.mu.Unlock()
		if onChange != nil {
			onChange()
		}
		return nil, queueRejected
	}
	if onChange != nil {
		onChange()
	}
	select {
	case q.running <- struct{}{}:
		if onChange != nil {
			onChange()
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				<-q.running
				<-q.admitted
				if onChange != nil {
					onChange()
				}
			})
		}, queueAdmitted
	case <-ctx.Done():
		<-q.admitted
		q.mu.Lock()
		q.canceled++
		q.mu.Unlock()
		if onChange != nil {
			onChange()
		}
		return nil, queueCanceled
	}
}

func (q *requestQueue) recordFailure(failure queueFailure) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failures = append(q.failures, failure)
	if len(q.failures) > 100 {
		q.failures = append([]queueFailure(nil), q.failures[len(q.failures)-100:]...)
	}
}

func (q *requestQueue) snapshot(method, path, group string, maxConcurrent, queueLimit int) queueRouteStatus {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return queueRouteStatus{
		Method: method, Path: path, Group: group, MaxConcurrent: maxConcurrent, QueueLimit: queueLimit,
		Running: len(q.running), Waiting: len(q.admitted) - len(q.running),
		Rejected: q.rejected, Canceled: q.canceled,
	}
}

func (q *requestQueue) failureSnapshot() []queueFailure {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return append([]queueFailure(nil), q.failures...)
}
