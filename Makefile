# CLI Snitch Makefile
.PHONY: build clean test install uninstall brew-formula package release

# Variables
BINARY_NAME=cli-snitch
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Default target
all: build

# Build the binary
build:
	@echo "Building CLI Snitch v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/cli-snitch
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Build for multiple architectures (for releases)
build-all:
	@echo "Building for multiple architectures..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/cli-snitch
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/cli-snitch
	@echo "Built binaries for darwin/amd64 and darwin/arm64"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)

# Install locally (requires sudo for /usr/local/bin)
install: build
	@echo "Installing CLI Snitch to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "CLI Snitch installed successfully"

# Uninstall from system
uninstall:
	@echo "Removing CLI Snitch from /usr/local/bin..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "CLI Snitch uninstalled"

# Test the Homebrew formula locally
brew-test:
	@echo "Testing Homebrew formula..."
	brew install --build-from-source ./Formula/cli-snitch.rb

# Create release package
package: build-all
	@echo "Creating release packages..."
	@mkdir -p $(BUILD_DIR)/packages
	cd $(BUILD_DIR) && tar -czf packages/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	cd $(BUILD_DIR) && tar -czf packages/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	@echo "Packages created in $(BUILD_DIR)/packages/"

# Generate SHA256 for Homebrew formula
sha256:
	@echo "Generating SHA256 for release..."
	@if [ ! -f "$(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz" ]; then \
		echo "Package not found. Run 'make package' first."; \
		exit 1; \
	fi
	@shasum -a 256 $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz

# Show current version
version:
	@echo $(VERSION)

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	go mod tidy
	go mod download
	@echo "Development environment ready"

# Quick development build and test
dev: build
	@echo "Running development test..."
	./$(BUILD_DIR)/$(BINARY_NAME) --help

# Help target
help:
	@echo "CLI Snitch Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build the binary"
	@echo "  build-all   Build for multiple architectures"
	@echo "  test        Run tests"
	@echo "  clean       Clean build artifacts"
	@echo "  install     Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall   Remove from /usr/local/bin (requires sudo)"
	@echo "  package     Create release packages"
	@echo "  sha256      Generate SHA256 for Homebrew formula"
	@echo "  brew-test   Test Homebrew formula locally"
	@echo "  version     Show current version"
	@echo "  dev-setup   Setup development environment"
	@echo "  dev         Quick development build and test"
	@echo "  help        Show this help message" 