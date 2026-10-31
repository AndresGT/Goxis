package log

import (
	"strings"
	"testing"
)

func TestRingBufferKeepsNewestCompleteLines(t *testing.T) {
	buffer := NewRingBuffer(2)
	_, _ = buffer.Write([]byte("first\nsecond"))
	if got := buffer.Snapshot(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("partial snapshot=%q", got)
	}
	_, _ = buffer.Write([]byte(" line\nthird\nfourth\n"))
	got := buffer.Snapshot()
	if len(got) != 2 || got[0] != "third" || got[1] != "fourth" {
		t.Fatalf("snapshot=%q", got)
	}
}

func TestLoggerCanWriteToAddedDestination(t *testing.T) {
	var original, extra strings.Builder
	logger := New(WithWriter(&original), WithColor(false), WithTimeFormat(""))
	logger.AddWriter(&extra)
	logger.Info("captured")
	if !strings.Contains(original.String(), "captured") || !strings.Contains(extra.String(), "captured") {
		t.Fatalf("original=%q extra=%q", original.String(), extra.String())
	}
}

func TestRingBufferBoundsLineLengthAndStripsColorCodes(t *testing.T) {
	buffer := NewRingBuffer(1)
	_, _ = buffer.Write([]byte("\x1b[32mgreen\x1b[0m\n"))
	line := buffer.Snapshot()[0]
	if line != "green" {
		t.Fatalf("ANSI sequence not removed: %q", line)
	}
	_, _ = buffer.Write([]byte(strings.Repeat("x", maxRingBufferLineBytes+100)))
	if got := len(buffer.Snapshot()[0]); got > maxRingBufferLineBytes+20 {
		t.Fatalf("retained oversized line (%d bytes)", got)
	}
}
