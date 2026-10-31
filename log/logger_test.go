package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLogLevelsAndColors(t *testing.T) {
	var output bytes.Buffer
	log := New(WithLevel(LevelTrace), WithWriter(&output), WithTimeFormat(""))

	oldExit := exitProcess
	var exitCode int
	exitProcess = func(code int) { exitCode = code }
	t.Cleanup(func() { exitProcess = oldExit })

	levels := []Level{LevelTrace, LevelDebug, LevelInfo, LevelSuccess, LevelWarn, LevelError, LevelFatal, LevelPanic}
	for _, level := range levels {
		func() {
			defer func() { _ = recover() }()
			log.Log(level, "message-"+level.String())
		}()
	}

	got := output.String()
	for _, level := range levels {
		want := level.Color() + level.Prefix() + colorReset + " message-" + level.String()
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain colored %s record %q", level, want)
		}
	}
	if exitCode != 1 {
		t.Errorf("Fatal exit code = %d, want 1", exitCode)
	}
}

func TestLogLevelFilter(t *testing.T) {
	var output bytes.Buffer
	log := New(WithLevel(LevelWarn), WithWriter(&output), WithColor(false), WithTimeFormat(""))
	log.Info("hidden")
	log.Warn("visible")

	got := output.String()
	if strings.Contains(got, "hidden") || !strings.Contains(got, "visible") {
		t.Fatalf("unexpected filtered output: %q", got)
	}
	if strings.Contains(got, "\033[") {
		t.Fatalf("color escape found with colors disabled: %q", got)
	}
}

func TestJSONFormatAndFields(t *testing.T) {
	var output bytes.Buffer
	log := New(WithWriter(&output), WithFormat(FormatJSON), WithTimeFormat(""))
	log.InfoWithFields("created", map[string]any{"user_id": "u-123", "active": true})

	var record Record
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if record.Level != "INFO" || record.Message != "created" {
		t.Fatalf("unexpected JSON record: %+v", record)
	}
	if record.Fields["user_id"] != "u-123" || record.Fields["active"] != true {
		t.Fatalf("unexpected JSON fields: %#v", record.Fields)
	}
}

func TestHTTPRequestWithIDInTextAndJSON(t *testing.T) {
	const requestID = "00112233445566778899aabbccddeeff"
	var textOutput bytes.Buffer
	textLogger := New(WithWriter(&textOutput), WithColor(false), WithTimeFormat(""))
	textLogger.HTTPRequestWithID("GET", "/items", 200, "127.0.0.1", 5*time.Millisecond, requestID)
	if !strings.Contains(textOutput.String(), "request_id="+requestID) {
		t.Fatalf("request ID missing from text access log: %q", textOutput.String())
	}

	var jsonOutput bytes.Buffer
	jsonLogger := New(WithWriter(&jsonOutput), WithFormat(FormatJSON), WithTimeFormat(""))
	jsonLogger.HTTPRequestWithID("GET", "/items", 200, "127.0.0.1", 5*time.Millisecond, requestID)
	var record Record
	if err := json.Unmarshal(bytes.TrimSpace(jsonOutput.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Fields["request_id"] != requestID {
		t.Fatalf("request ID missing from JSON access log: %#v", record.Fields)
	}
}

func TestParseLevelAndFormat(t *testing.T) {
	level, err := ParseLevel("  WaRn  ")
	if err != nil || level != LevelWarn {
		t.Fatalf("ParseLevel() = %v, %v; want WARN, nil", level, err)
	}
	format, err := ParseFormat(" JSON ")
	if err != nil || format != FormatJSON {
		t.Fatalf("ParseFormat() = %v, %v; want JSON, nil", format, err)
	}
	if _, err := ParseLevel("verbose"); !errors.Is(err, ErrInvalidLevel) {
		t.Errorf("ParseLevel(invalid) error = %v, want ErrInvalidLevel", err)
	}
	if _, err := ParseFormat("xml"); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("ParseFormat(invalid) error = %v, want ErrInvalidFormat", err)
	}
}

func TestPanicMode(t *testing.T) {
	var output bytes.Buffer
	log := New(WithWriter(&output), WithTimeFormat(""))
	defer func() {
		if got := recover(); got != "stop" {
			t.Errorf("Panic() recovered %v, want %q", got, "stop")
		}
		if !strings.Contains(output.String(), "[PANIC]") {
			t.Errorf("panic message was not logged: %q", output.String())
		}
	}()
	log.Panic("stop")
}
