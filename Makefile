# Makefile for wrapp - Redis process wrapper tool
# Optimized for NVIDIA Orin AGX (Cortex-A78AE, Armv8.2-A)

BINARY_NAME := wrapp
BUILD_DIR := build
GO := go
INSTALL_DIR := /usr/local/bin

# Target architecture for NVIDIA Orin AGX
GOOS := linux
GOARCH := arm64
# Cortex-A78AE supports Armv8.2-A with crypto and LSE (Large System Extensions)
GOARM64 := v8.2,crypto,lse

# Common build flags
COMMON_FLAGS := -trimpath
RELEASE_FLAGS := -ldflags="-s -w" $(COMMON_FLAGS)
DEBUG_FLAGS := -tags debug $(COMMON_FLAGS)
ENV_FLAGS := GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM64=$(GOARM64)

.PHONY: all build release dev clean install uninstall test

# Default to release build
all: release

# Release build - optimized for production (no debug output)
release:
	@echo "Building RELEASE $(BINARY_NAME) for NVIDIA Orin AGX..."
	@mkdir -p $(BUILD_DIR)
	$(ENV_FLAGS) $(GO) build $(RELEASE_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Release build complete: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "  Size: $$(du -h $(BUILD_DIR)/$(BINARY_NAME) | cut -f1)"
	@echo "  Debug: DISABLED"

# Development build - includes debug output
dev:
	@echo "Building DEBUG $(BINARY_NAME) for NVIDIA Orin AGX..."
	@mkdir -p $(BUILD_DIR)
	$(ENV_FLAGS) $(GO) build $(DEBUG_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-debug .
	@echo "Debug build complete: $(BUILD_DIR)/$(BINARY_NAME)-debug"
	@echo "  Size: $$(du -h $(BUILD_DIR)/$(BINARY_NAME)-debug | cut -f1)"
	@echo "  Debug: ENABLED"

# Alias for compatibility
build: release

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@$(GO) clean -cache -testcache
	@echo "Clean complete"

install: release
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo chmod 755 $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installation complete (release version)"

install-dev: dev
	@echo "Installing debug $(BINARY_NAME) to $(INSTALL_DIR)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME)-debug $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo chmod 755 $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installation complete (debug version)"

uninstall:
	@echo "Uninstalling $(BINARY_NAME) from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstallation complete"

test:
	@echo "Running tests..."
	$(GO) test -v -race ./...


# Update dependencies
deps:
	@echo "Updating dependencies..."
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "Dependencies updated"

# Show version info
version:
	@$(GO) version
	@echo "Module: $$($(GO) list -m)"

help:
	@echo "Available targets:"
	@echo "  release     - Build production version (no debug output)"
	@echo "  dev         - Build debug version (with debug output)"
	@echo "  build       - Alias for release"
	@echo "  clean       - Remove binaries and clear caches"
	@echo "  install     - Install release version to $(INSTALL_DIR)"
	@echo "  install-dev - Install debug version to $(INSTALL_DIR)"
	@echo "  uninstall   - Remove from $(INSTALL_DIR)"
	@echo "  test        - Run tests"
	@echo "  deps        - Update Go dependencies"
	@echo "  version     - Show Go and module version"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Target Architecture: NVIDIA Orin AGX (Cortex-A78AE)"
	@echo "  GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM64=$(GOARM64)"
	@echo ""
	@echo "Debug output is controlled via build tags:"
	@echo "  make dev     - Builds with debug output enabled"
	@echo "  make release - Builds without debug output"