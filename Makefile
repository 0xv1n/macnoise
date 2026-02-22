BINARY     := macnoise
CMD        := ./cmd/macnoise
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -ldflags "-X main.version=$(VERSION)"
GOOS_DARWIN := darwin

.PHONY: build build-amd64 build-arm64 test test-integration lint fmt vet clean coverage install-hooks

## Build for host OS (development)
build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

## Build Darwin amd64 release binary
build-amd64:
	GOOS=$(GOOS_DARWIN) GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 $(CMD)

## Build Darwin arm64 release binary
build-arm64:
	GOOS=$(GOOS_DARWIN) GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 $(CMD)

## Build both macOS architectures
release: build-amd64 build-arm64

## Run unit tests (no macOS required)
test:
	go test -race -count=1 ./pkg/... ./internal/...

## Run integration tests (macOS only)
test-integration:
	go test -tags integration -race -count=1 ./modules/...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

coverage:
	go test -race -coverprofile=coverage.out ./pkg/... ./internal/...
	go tool cover -html=coverage.out

## Install git hooks (one-time setup per clone)
install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-push
	@echo "Git hooks installed. Push will run lint + unit tests."

clean:
	rm -f $(BINARY) $(BINARY)-darwin-amd64 $(BINARY)-darwin-arm64 coverage.out
