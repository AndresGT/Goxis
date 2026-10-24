package goxis

import (
	"net/url"
	"strings"
	"testing"
)

func TestSafeRequestURIRedactsCredentials(t *testing.T) {
	u, err := url.Parse("/items?q=invoice&access_token=topsecret&api_key=abc")
	if err != nil {
		t.Fatal(err)
	}
	got := safeRequestURI(u)
	if strings.Contains(got, "topsecret") || strings.Contains(got, "abc") || !strings.Contains(got, "invoice") {
		t.Fatalf("unexpected sanitized URI: %q", got)
	}
}

func TestSafeRequestURIRedactsMalformedQuery(t *testing.T) {
	u := &url.URL{Path: "/items", RawQuery: "token=%zz"}
	got := safeRequestURI(u)
	if strings.Contains(got, "%zz") {
		t.Fatalf("malformed query leaked: %q", got)
	}
}
