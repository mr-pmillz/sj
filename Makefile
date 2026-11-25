BINARY    := sj
MODULE    := github.com/mr-pmillz/sj
BUILD_DIR := bin
COVER_DIR := coverage

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE).version=$(VERSION) \
	-X $(MODULE).commit=$(COMMIT) \
	-X $(MODULE).date=$(BUILD_DATE)

.PHONY: all build test test-petstore test-petstore-live test-race test-coverage lint fmt vet install clean tidy

all: lint test build

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/sj

test: ## Run all tests
	@if ! command -v tparse >/dev/null 2>&1; then \
			echo "tparse not installed; installing..."; \
			go install github.com/mfridman/tparse@latest; \
	fi
	@echo "🧪 Running all tests..."
	@mkdir -p $(COVER_DIR)
	go test -json -covermode=atomic -coverprofile=$(COVER_DIR)/coverage.out ./... | tparse -all

test-race:
	go test ./... -count=1 -race

test-petstore: ## Run the Petstore contract and fuzz benchmarks on a local replica and write reports to coverage/petstore
	SJ_SAVE_PETSTORE_REPORTS=1 go test ./cmd/sj -count=1 -v -run '^TestPetstore(Contract|Fuzz)Benchmark$$'

test-petstore-live: ## Fuzz the public Petstore sandbox (several hundred paced requests) and compare with tests/petstore/answer-key.yaml
	SJ_PETSTORE_LIVE=1 go test ./cmd/sj -count=1 -v -timeout=20m -run '^TestPetstoreLiveBenchmark$$'

test-coverage:
	@mkdir -p $(COVER_DIR)
	go test ./... -count=1 -race -coverprofile=$(COVER_DIR)/coverage.out -covermode=atomic
	go tool cover -func=$(COVER_DIR)/coverage.out
	go tool cover -html=$(COVER_DIR)/coverage.out -o $(COVER_DIR)/coverage.html
	@echo "Coverage report: $(COVER_DIR)/coverage.html"

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run --config .golangci-lint.yml -v --timeout 10m

fmt:
	go fmt ./...
	goimports -w .

vet:
	go vet ./...

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/sj

clean:
	rm -rf $(BUILD_DIR) $(COVER_DIR)
	go clean

tidy:
	go mod tidy
