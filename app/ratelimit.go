package goxis

import (
	"net"
	"sync"
	"time"
)

type routeRateEntry struct {
	count   int
	expires time.Time
}
type routeLimiter struct {
	mu      sync.Mutex
	limit   int
	clients map[string]routeRateEntry
}

func newRouteLimiter(limit int) *routeLimiter {
	if limit <= 0 {
		return nil
	}
	return &routeLimiter{limit: limit, clients: make(map[string]routeRateEntry)}
}

func (l *routeLimiter) allow(remoteAddr string, now time.Time) bool {
	key := remoteIP(remoteAddr)
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.clients[key]
	if !exists || !now.Before(entry.expires) {
		if !exists && len(l.clients) >= 4096 {
			for client, item := range l.clients {
				if !now.Before(item.expires) {
					delete(l.clients, client)
				}
			}
			if len(l.clients) >= 4096 {
				return false
			}
		}
		entry = routeRateEntry{expires: now.Add(time.Minute)}
	}
	if entry.count >= l.limit {
		l.clients[key] = entry
		return false
	}
	entry.count++
	l.clients[key] = entry
	return true
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}
