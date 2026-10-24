package goxis

import (
	"net/http"
	"testing"
	"time"
)

func TestHTTPServerUsesSecureDefaults(t *testing.T) {
	server, err := New().NewHTTPServer(":0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes <= 0 {
		t.Fatalf("server has unbounded defaults: %+v", server)
	}
}

func TestHTTPServerConfigCanDisableWriteTimeoutForStreaming(t *testing.T) {
	cfg := DefaultHTTPServerConfig()
	cfg.WriteTimeout = 0
	server, err := New(WithHTTPServerConfig(cfg)).NewHTTPServer(":0", http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	if server.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout=%s, want 0", server.WriteTimeout)
	}
	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout=%s", server.ReadHeaderTimeout)
	}
}
