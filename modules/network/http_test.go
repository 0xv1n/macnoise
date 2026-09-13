package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestHTTPGenerate_PerformsExactRequest(t *testing.T) {
	type observedRequest struct {
		method      string
		body        string
		contentType string
		runID       string
	}
	observed := make(chan observedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		observed <- observedRequest{
			method:      request.Method,
			body:        string(body),
			contentType: request.Header.Get("Content-Type"),
			runID:       request.URL.Query().Get("mn"),
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	ctx := module.ContextWithRunID(context.Background(), "httprun42")
	params := module.Params{
		"target":       server.URL + "/collect",
		"method":       http.MethodPost,
		"body":         "decoy payload",
		"content_type": "text/plain",
	}
	var events []module.TelemetryEvent
	if err := (&netHTTP{}).Generate(ctx, params, captureNetworkEvents(&events)); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	got := <-observed
	want := observedRequest{http.MethodPost, "decoy payload", "text/plain", "httprun42"}
	if got != want {
		t.Errorf("request = %+v, want %+v", got, want)
	}
	if len(events) != 1 || events[0].EventType != "http_post" || events[0].Outcome != module.OutcomeExecuted {
		t.Fatalf("events = %+v, want one executed http_post", events)
	}
	if events[0].Details["status_code"] != http.StatusAccepted || events[0].Details["request_bytes"] != len("decoy payload") {
		t.Errorf("event details = %+v", events[0].Details)
	}
}

func TestHTTPGenerate_RefusedIsDenied(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	var events []module.TelemetryEvent
	if err := (&netHTTP{}).Generate(context.Background(), module.Params{"target": target}, captureNetworkEvents(&events)); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 || events[0].EventType != "http_get" || events[0].Outcome != module.OutcomeDenied || events[0].Error == "" {
		t.Fatalf("events = %+v, want one denied request", events)
	}
}

func TestHTTPGenerate_RepeatsRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	var events []module.TelemetryEvent
	if err := (&netHTTP{}).Generate(context.Background(), module.Params{"target": server.URL, "count": "3"}, captureNetworkEvents(&events)); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if requests.Load() != 3 || len(events) != 3 {
		t.Fatalf("got %d requests and %d events, want 3 each", requests.Load(), len(events))
	}
	for index, event := range events {
		if event.Details["attempt"] != index+1 || event.Details["total"] != 3 {
			t.Errorf("event %d details = %+v", index, event.Details)
		}
	}
}

func TestHTTPGenerate_DoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/start" {
			http.Redirect(w, request, "/next", http.StatusFound)
		}
	}))
	defer server.Close()

	var events []module.TelemetryEvent
	params := module.Params{"target": server.URL + "/start", "method": http.MethodPost, "body": "payload"}
	if err := (&netHTTP{}).Generate(context.Background(), params, captureNetworkEvents(&events)); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("server received %d requests, want only the declared request", requests.Load())
	}
	if len(events) != 1 || events[0].Details["status_code"] != http.StatusFound {
		t.Fatalf("events = %+v, want redirect response", events)
	}
}

func TestHTTPGenerate_CancelInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		close(started)
		cancel()
		<-request.Context().Done()
	}))
	defer server.Close()
	defer cancel()

	var events []module.TelemetryEvent
	start := time.Now()
	err := (&netHTTP{}).Generate(ctx, module.Params{"target": server.URL}, captureNetworkEvents(&events))
	select {
	case <-started:
	default:
		t.Fatal("request never reached the server")
	}
	if !errors.Is(err, context.Canceled) || len(events) != 0 {
		t.Fatalf("Generate = %v, events = %+v; want canceled with no completed event", err, events)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("cancellation took %v, want less than 2s", elapsed)
	}
}

func TestHTTPGenerate_CancelBetweenRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var events []module.TelemetryEvent
	start := time.Now()
	err := (&netHTTP{}).Generate(ctx, module.Params{"target": server.URL, "count": "3", "interval": "3"}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(events) != 1 {
		t.Fatalf("Generate = %v, events = %+v; want canceled after one request", err, events)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("cancellation waited %v for the next interval", elapsed)
	}
}

func TestHTTPValidateParams(t *testing.T) {
	mod := &netHTTP{}
	for _, target := range []string{"example.com", "ftp://example.com", "http://"} {
		if err := mod.ValidateParams(module.Params{"target": target}); err == nil {
			t.Errorf("ValidateParams(%q) succeeded", target)
		}
	}
	if err := mod.ValidateParams(module.Params{"target": "https://example.com/path"}); err != nil {
		t.Errorf("ValidateParams(valid URL): %v", err)
	}
	if err := mod.ValidateParams(module.Params{"target": "https://example.com", "method": "PATCH"}); err == nil {
		t.Error("ValidateParams accepted PATCH")
	}
}
