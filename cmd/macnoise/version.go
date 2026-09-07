package main

// version is the canonical build version string.
// It defaults to "0.1.0" and is overwritten at build time via LDFLAGS:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/macnoise
//
// The Makefile and release CI pipeline inject the value automatically from
// `git describe --tags --always --dirty`, so no source edit is needed at
// release time - tag the commit and let the build system handle the rest.
// The fallback string below is kept in sync automatically by release-please.
var version = "0.6.0" // x-release-please-version
