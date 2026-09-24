BINARY      := envleak
PKG         := github.com/dotMuny/EnvLeak
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)
GO          ?= go
GOBIN       ?= $(shell $(GO) env GOPATH)/bin

export CGO_ENABLED = 0

.PHONY: all build install test test-race cover lint fmt vet tidy fuzz clean docs demo testdata bench snapshot

all: build

build: ## Build the static binary into ./bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/envleak

install:
	$(GO) install -trimpath -ldflags '$(LDFLAGS)' ./cmd/envleak

test: ## Run the full test suite
	$(GO) test ./... -count=1

test-race:
	CGO_ENABLED=1 $(GO) test ./... -race -count=1

cover: ## Coverage report over internal/
	$(GO) test ./internal/... -covermode=atomic -coverprofile=coverage.out -count=1
	@$(GO) tool cover -func=coverage.out | tail -n 1
	@$(GO) tool cover -html=coverage.out -o coverage.html

fuzz: ## Short fuzzing pass over the rule parser and the entropy engine
	$(GO) test ./internal/rules   -run=XXX -fuzz=FuzzParse   -fuzztime=30s
	$(GO) test ./internal/detect  -run=XXX -fuzz=FuzzEntropy -fuzztime=30s

lint: ## golangci-lint with the project ruleset
	$(GOBIN)/golangci-lint run ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

testdata: ## Regenerate testdata/repo for manual inspection (tests build their own)
	$(GO) run ./internal/testcorpus/cmd testdata/repo

docs: build ## Regenerate docs/rules.md from the embedded catalogue
	./bin/$(BINARY) rules --markdown > docs/rules.md

demo: build ## Regenerate the demo SVG from a real run
	python3 hack/mkdemo.py

bench:
	$(GO) test ./internal/... -run=XXX -bench=. -benchmem

snapshot: ## Cross-compile all release targets without publishing
	$(GOBIN)/goreleaser release --snapshot --clean

clean:
	rm -rf bin dist coverage.out coverage.html
