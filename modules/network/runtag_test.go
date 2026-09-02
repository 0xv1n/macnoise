package network

import (
	"net/url"
	"strings"
	"testing"
)

func TestTagURL_AddsRunID(t *testing.T) {
	got := tagURL("http://example.com/path", "deadbeef01234567")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}
	if u.Query().Get("mn") != "deadbeef01234567" {
		t.Errorf("mn query param = %q, want deadbeef01234567 (%s)", u.Query().Get("mn"), got)
	}
	if !strings.HasPrefix(got, "http://example.com/path") {
		t.Errorf("base URL not preserved: %s", got)
	}
}

func TestTagURL_PreservesExistingQuery(t *testing.T) {
	got := tagURL("http://example.com/?a=1", "abc")
	u, _ := url.Parse(got)
	if u.Query().Get("a") != "1" {
		t.Errorf("existing query dropped: %s", got)
	}
	if u.Query().Get("mn") != "abc" {
		t.Errorf("run ID not added: %s", got)
	}
}

func TestTagURL_EmptyRunIDUnchanged(t *testing.T) {
	if got := tagURL("http://example.com", ""); got != "http://example.com" {
		t.Errorf("empty run ID should leave URL unchanged, got %s", got)
	}
}
