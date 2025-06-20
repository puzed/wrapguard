.PHONY: all build clean test

# Build variables
GO_MODULE = github.com/puzed/wrapguard
BINARY_NAME = wrapguard
LIBRARY_NAME = libwrapguard.so
VERSION = 1.0.0-dev

# Build flags
GO_BUILD_FLAGS = -ldflags="-s -w -X main.version=$(VERSION)"
C_BUILD_FLAGS = -shared -fPIC -ldl

# Default target
all: build

# Build both Go binary and C library
build: $(BINARY_NAME) $(LIBRARY_NAME)

# Build Go binary
$(BINARY_NAME): *.go go.mod go.sum
	@echo "Building Go binary..."
	go mod tidy
	go build $(GO_BUILD_FLAGS) -o $(BINARY_NAME) .

# Build C library
$(LIBRARY_NAME): lib/intercept.c
	@echo "Building C library..."
	gcc $(C_BUILD_FLAGS) -o $(LIBRARY_NAME) lib/intercept.c

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME) $(LIBRARY_NAME)
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
debug: C_BUILD_FLAGS += -g -O0
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

# Build for multiple platforms
build-all: build-linux build-darwin

build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_NAME)-linux-amd64 .
	gcc $(C_BUILD_FLAGS) -o libwrapguard-linux-amd64.so lib/intercept.c

build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BINARY_NAME)-darwin-arm64 .
	gcc $(C_BUILD_FLAGS) -o libwrapguard-darwin.dylib lib/intercept.c

# Run demo
demo: build
	@echo "Running demo..."
	cd demo && ./setup.sh && docker-compose up

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build both binary and library (default)"
	@echo "  build        - Build both binary and library"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  debug        - Build debug version"
	@echo "  deps         - Install dependencies"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Run linter"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  demo         - Run demo"
	@echo "  help         - Show this help"