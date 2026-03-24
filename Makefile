SHELL := /bin/bash

.PHONY: all build build-target build-linux build-linux-amd64 build-linux-arm64 build-macos build-macos-amd64 build-macos-arm64 build-macos-universal build-all clean test test-coverage deps fmt lint smoke-macos help

# Build variables
GO_MODULE = github.com/puzed/wrapguard
BINARY_NAME = wrapguard
VERSION ?= 1.0.0-dev
DIST_DIR ?= dist
TARGET_GOOS ?= $(shell go env GOOS)
TARGET_GOARCH ?= $(shell go env GOARCH)
TARGET_DIR ?= .
GO_BUILD_FLAGS = -ldflags="-s -w -X main.version=$(VERSION)"
LIBRARY_NAME = $(if $(filter darwin,$(TARGET_GOOS)),libwrapguard.dylib,libwrapguard.so)

ifeq ($(TARGET_GOOS),darwin)
  ifeq ($(TARGET_GOARCH),amd64)
    DARWIN_ARCH = x86_64
  else ifeq ($(TARGET_GOARCH),arm64)
    DARWIN_ARCH = arm64
  else
    DARWIN_ARCH = $(TARGET_GOARCH)
  endif
  C_COMPILER ?= clang
  GO_CGO_ENV = CGO_ENABLED=1 CC="$(C_COMPILER)" CGO_CFLAGS="-arch $(DARWIN_ARCH)" CGO_LDFLAGS="-arch $(DARWIN_ARCH)"
  C_ARCH_FLAGS = -arch $(DARWIN_ARCH)
  C_SHARED_FLAGS = -dynamiclib
  C_WARNING_FLAGS = -Wall -Wextra -Wpedantic -O2
  C_LINK_FLAGS = -Wl,-undefined,dynamic_lookup
else
  C_COMPILER ?= gcc
  GO_CGO_ENV = CGO_ENABLED=1 CC="$(C_COMPILER)"
  C_ARCH_FLAGS =
  C_SHARED_FLAGS = -shared -fPIC
  C_WARNING_FLAGS = -Wall -Wextra -Wpedantic -O2
  C_LINK_FLAGS = -ldl
endif

# Default target
all: build

# Build the current host platform into the requested output directory
build: build-target

build-target:
	@mkdir -p "$(TARGET_DIR)"
	@echo "Building $(TARGET_GOOS)/$(TARGET_GOARCH) into $(TARGET_DIR)..."
	@GOOS=$(TARGET_GOOS) GOARCH=$(TARGET_GOARCH) $(GO_CGO_ENV) go build $(GO_BUILD_FLAGS) -o "$(TARGET_DIR)/$(BINARY_NAME)" .
	@$(C_COMPILER) $(C_ARCH_FLAGS) $(C_SHARED_FLAGS) $(C_WARNING_FLAGS) lib/intercept.c $(C_LINK_FLAGS) -o "$(TARGET_DIR)/$(LIBRARY_NAME)"

build-linux: TARGET_GOOS = linux
build-linux: TARGET_DIR = $(DIST_DIR)/linux-$(TARGET_GOARCH)
build-linux: build-target

build-linux-amd64:
	@$(MAKE) build-linux TARGET_GOARCH=amd64

build-linux-arm64:
	@$(MAKE) build-linux TARGET_GOARCH=arm64 C_COMPILER=aarch64-linux-gnu-gcc

build-macos: TARGET_GOOS = darwin
build-macos: TARGET_DIR = $(DIST_DIR)/darwin-$(TARGET_GOARCH)
build-macos: build-target

build-macos-amd64:
	@$(MAKE) build-macos TARGET_GOARCH=amd64

build-macos-arm64:
	@$(MAKE) build-macos TARGET_GOARCH=arm64

build-macos-universal: TARGET_GOOS = darwin
build-macos-universal:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "build-macos-universal must be run on macOS"; \
		exit 1; \
	fi
	@set -euo pipefail; \
	stage_dir="$$(mktemp -d)"; \
	final_dir="$(DIST_DIR)/darwin-universal"; \
	trap 'rm -rf "$$stage_dir"' EXIT; \
	$(MAKE) build-target TARGET_GOOS=darwin TARGET_GOARCH=amd64 TARGET_DIR="$$stage_dir/amd64" C_COMPILER=clang; \
	$(MAKE) build-target TARGET_GOOS=darwin TARGET_GOARCH=arm64 TARGET_DIR="$$stage_dir/arm64" C_COMPILER=clang; \
	mkdir -p "$$final_dir"; \
	lipo -create "$$stage_dir/amd64/$(BINARY_NAME)" "$$stage_dir/arm64/$(BINARY_NAME)" -output "$$final_dir/$(BINARY_NAME)"; \
	lipo -create "$$stage_dir/amd64/$(LIBRARY_NAME)" "$$stage_dir/arm64/$(LIBRARY_NAME)" -output "$$final_dir/$(LIBRARY_NAME)"; \
	chmod +x "$$final_dir/$(BINARY_NAME)"; \
	echo "Built universal macOS binaries in $$final_dir"

build-all: build-linux-amd64 build-linux-arm64 build-macos-amd64 build-macos-arm64

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf "$(DIST_DIR)" "$(BINARY_NAME)" "$(LIBRARY_NAME)"
	go clean

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -cover ./...

# Build debug version
debug: GO_BUILD_FLAGS = -ldflags="-X main.version=$(VERSION)-debug"
debug: C_WARNING_FLAGS += -g -O0
debug: build

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download

# Format code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	go vet ./...

# Validate a local macOS package end to end
smoke-macos:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "smoke-macos must be run on macOS"; \
		exit 1; \
	fi
	@set -euo pipefail; \
	$(MAKE) build-macos TARGET_GOARCH=$(TARGET_GOARCH); \
	staging="$$(mktemp -d)"; \
	package_dir="$$staging/package"; \
	verify_dir="$$staging/verify"; \
	mkdir -p "$$package_dir" "$$verify_dir"; \
	cp "$(DIST_DIR)/darwin-$(TARGET_GOARCH)/$(BINARY_NAME)" "$$package_dir/"; \
	cp "$(DIST_DIR)/darwin-$(TARGET_GOARCH)/$(LIBRARY_NAME)" "$$package_dir/"; \
	cp README.md example-wg0.conf "$$package_dir/"; \
	tar -C "$$package_dir" -czf "$$staging/$(BINARY_NAME)-macos-smoke.tar.gz" $(BINARY_NAME) $(LIBRARY_NAME) README.md example-wg0.conf; \
	tar -xzf "$$staging/$(BINARY_NAME)-macos-smoke.tar.gz" -C "$$verify_dir"; \
	test -x "$$verify_dir/$(BINARY_NAME)"; \
	test -f "$$verify_dir/$(LIBRARY_NAME)"; \
	chmod +x "$$verify_dir/$(BINARY_NAME)"; \
	"$$verify_dir/$(BINARY_NAME)" --version; \
	"$$verify_dir/$(BINARY_NAME)" --help; \
	rm -rf "$$staging"

# Run demo
demo: build
	@echo "Running demo..."
	cd demo && ./setup.sh && docker-compose up

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Build the current host platform (default)"
	@echo "  build            - Build the current host platform"
	@echo "  build-linux      - Build a Linux package into dist/"
	@echo "  build-linux-amd64 - Build a Linux amd64 package into dist/"
	@echo "  build-linux-arm64 - Build a Linux arm64 package into dist/"
	@echo "  build-macos      - Build a macOS package into dist/"
	@echo "  build-macos-amd64 - Build a macOS amd64 package into dist/"
	@echo "  build-macos-arm64 - Build a macOS arm64 package into dist/"
	@echo "  build-macos-universal - Build a universal macOS package into dist/"
	@echo "  build-all        - Build all packaged Linux and macOS variants"
	@echo "  clean            - Clean build artifacts"
	@echo "  test             - Run tests"
	@echo "  test-coverage    - Run tests with coverage"
	@echo "  debug            - Build debug version"
	@echo "  deps             - Install dependencies"
	@echo "  fmt              - Format Go code"
	@echo "  lint             - Run go vet"
	@echo "  smoke-macos      - Validate a local macOS package end to end"
	@echo "  demo             - Run demo"
	@echo "  help             - Show this help"
