package goxis

import (
	"context"
	"sync"
)

const maxRouteQueueCapacity = 65536

// requestQueue places a hard admission bound around one route while limiting
// the number of handlers running concurrently.
type requestQueue struct {
	admitted chan struct{}
	running  chan struct{}
}

func newRequestQueue(concurrency, waiting int) *requestQueue {
	if concurrency <= 0 {
		return nil
	}
	return &requestQueue{admitted: make(chan struct{}, concurrency+waiting), running: make(chan struct{}, concurrency)}
}

func (q *requestQueue) acquire(ctx context.Context) (func(), bool) {
	select {
	case q.admitted <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case q.running <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-q.running; <-q.admitted }) }, true
	case <-ctx.Done():
		<-q.admitted
		return nil, false
	}
}
