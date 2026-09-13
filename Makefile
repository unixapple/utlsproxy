GO ?= go
GOTOOLCHAIN ?= go1.27.1
VERSION ?= 0.1.0-dev
export GOTOOLCHAIN

.PHONY: build test check fingerprint release
build:
	$(GO) build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/utlsproxy ./cmd/utlsproxy

test:
	$(GO) test -race ./...

check:
	$(GO) vet ./...

fingerprint: build
	./bin/utlsproxy test

release:
	bash scripts/release.sh '$(VERSION)'
