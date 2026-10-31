package log

import (
	"strings"
	"sync"
)

const maxRingBufferLineBytes = 16 * 1024

// RingBuffer is a bounded, concurrency-safe io.Writer for retaining recent
// log lines in memory. Oldest lines are discarded when the limit is reached.
type RingBuffer struct {
	mu        sync.RWMutex
	entries   []string
	capacity  int
	start     int
	length    int
	partial   strings.Builder
	truncated bool
	onLine    func(string)
}

// NewRingBuffer creates a buffer that retains at most maxEntries complete lines.
func NewRingBuffer(maxEntries int) *RingBuffer {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &RingBuffer{entries: make([]string, maxEntries), capacity: maxEntries}
}

func (b *RingBuffer) Write(p []byte) (int, error) {
	if b == nil {
		return len(p), nil
	}
	b.mu.Lock()
	completed := make([]string, 0, strings.Count(string(p), "\n"))
	for _, char := range p {
		if char == '\n' {
			line := b.partial.String()
			if b.truncated {
				line += " …[truncated]"
			}
			line = stripANSI(line)
			b.append(line)
			completed = append(completed, line)
			b.partial.Reset()
			b.truncated = false
			continue
		}
		if b.partial.Len() < maxRingBufferLineBytes {
			_ = b.partial.WriteByte(char)
		} else {
			b.truncated = true
		}
	}
	callback := b.onLine
	b.mu.Unlock()
	if callback != nil {
		for _, line := range completed {
			callback(line)
		}
	}
	return len(p), nil
}

// SetOnLine registers a callback invoked after each complete line is retained.
// Pass nil to disable notifications.
func (b *RingBuffer) SetOnLine(callback func(string)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.onLine = callback
	b.mu.Unlock()
}

func (b *RingBuffer) append(line string) {
	if b.length < b.capacity {
		index := (b.start + b.length) % b.capacity
		b.entries[index] = line
		b.length++
		return
	}
	b.entries[b.start] = line
	b.start = (b.start + 1) % b.capacity
}

// Snapshot returns a copy of the retained lines, oldest first.
func (b *RingBuffer) Snapshot() []string {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]string, b.length)
	for i := range result {
		result[i] = b.entries[(b.start+i)%b.capacity]
	}
	if b.partial.Len() > 0 {
		line := b.partial.String()
		if b.truncated {
			line += " …[truncated]"
		}
		result = append(result, stripANSI(line))
	}
	return result
}

func stripANSI(input string) string {
	var output strings.Builder
	for i := 0; i < len(input); {
		if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '[' {
			i += 2
			for i < len(input) && ((input[i] >= '0' && input[i] <= '9') || input[i] == ';') {
				i++
			}
			if i < len(input) && input[i] == 'm' {
				i++
				continue
			}
			continue
		}
		output.WriteByte(input[i])
		i++
	}
	return output.String()
}
