GO ?= go
VERSION ?= 0.1.0-dev
export GOTOOLCHAIN

.PHONY: build test check fingerprint release
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/utlsproxy ./cmd/utlsproxy

test:
	$(GO) test -race ./...

check:
	$(GO) vet ./...

fingerprint: build
	./bin/utlsproxy test

release:
	bash scripts/release.sh '$(VERSION)'
