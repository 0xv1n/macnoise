package network

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestBeaconGenerate_RequestsAndEvents(t *testing.T) {
	type request struct{ method, path, query, runID string }
	var mu sync.Mutex
	var requests []request
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, request{r.Method, r.URL.Path, r.URL.Query().Get("existing"), r.URL.Query().Get("mn")})
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = module.ContextWithRunID(ctx, "beaconrun42")
	var events []module.TelemetryEvent
	params := module.Params{"target": ts.URL + "/beacon?existing=keep", "count": "3", "interval": "0"}
	if err := (&c2Beacon{}).Generate(ctx, params, func(ev module.TelemetryEvent) { events = append(events, ev) }); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 || len(events) != 3 {
		t.Fatalf("got %d requests and %d events, want 3 each", len(requests), len(events))
	}
	for i, req := range requests {
		if req != (request{"GET", "/beacon", "keep", "beaconrun42"}) {
			t.Errorf("request %d = %+v", i, req)
		}
		ev := events[i]
		if ev.Module != "net_beacon" || ev.EventType != "http_beacon" || !ev.Success || ev.ResolvedOutcome() != module.OutcomeExecuted {
			t.Errorf("event %d = %+v", i, ev)
		}
		// An HTTP error response still proves that the request executed.
		if ev.Details["status"] != http.StatusServiceUnavailable || ev.Details["attempt"] != i+1 || ev.Details["total"] != 3 {
			t.Errorf("event %d details = %+v", i, ev.Details)
		}
		if ev.Details["url"] != ts.URL+"/beacon?existing=keep&mn=beaconrun42" {
			t.Errorf("event URL = %v", ev.Details["url"])
		}
	}
}

func TestBeaconGenerate_RefusedIsDenied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	var events []module.TelemetryEvent
	if err := (&c2Beacon{}).Generate(context.Background(), module.Params{"target": target, "count": "2", "interval": "0"}, func(ev module.TelemetryEvent) { events = append(events, ev) }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	for _, ev := range events {
		if ev.EventType != "http_beacon" || !ev.Success || ev.ResolvedOutcome() != module.OutcomeDenied || ev.Error == "" {
			t.Errorf("refused beacon = %+v", ev)
		}
	}
}

func TestBeaconGenerate_WaitsBetweenRequests(t *testing.T) {
	var mu sync.Mutex
	var arrivals []time.Time
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals = append(arrivals, time.Now())
		mu.Unlock()
	}))
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := (&c2Beacon{}).Generate(ctx, module.Params{"target": ts.URL, "count": "2", "interval": "1", "jitter": "0"}, func(module.TelemetryEvent) {}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(arrivals) != 2 {
		t.Fatalf("got %d requests, want 2", len(arrivals))
	}
	first, second := arrivals[0], arrivals[1]
	if gap := second.Sub(first); gap < time.Second {
		t.Errorf("requests only %v apart, want at least 1s", gap)
	}
}

func TestBeaconGenerate_CancelBetweenRequests(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []module.TelemetryEvent
	start := time.Now()
	err := (&c2Beacon{}).Generate(ctx, module.Params{"target": ts.URL, "count": "3", "interval": "3"}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
		cancel()
	})
	if !errors.Is(err, context.Canceled) || len(events) != 1 {
		t.Fatalf("err = %v, events = %d; want canceled after one event", err, len(events))
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("cancellation waited %v for the next interval", elapsed)
	}
}

func TestBeaconGenerate_CancelInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	started := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		cancel()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer ts.Close()
	defer close(release)
	var events []module.TelemetryEvent
	start := time.Now()
	err := (&c2Beacon{}).Generate(ctx, module.Params{"target": ts.URL, "count": "1"}, func(ev module.TelemetryEvent) { events = append(events, ev) })
	select {
	case <-started:
	default:
		t.Fatal("request never reached the server")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Generate = %v, want context.Canceled", err)
	}
	if len(events) != 0 {
		t.Errorf("canceled request emitted completed/denied events: %+v", events)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("in-flight cancellation took %v, want less than 2s", elapsed)
	}
}
