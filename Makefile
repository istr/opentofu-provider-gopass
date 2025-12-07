# terraform-provider-gopass Makefile
# ===================================

BINARY_NAME = terraform-provider-gopass
VERSION     = 0.1.0
OS_ARCH     = $(shell go env GOOS)_$(shell go env GOARCH)

# OpenTofu/Terraform plugin directories
TF_PLUGIN_DIR   = ~/.terraform.d/plugins
TOFU_PLUGIN_DIR = ~/.local/share/opentofu/plugins

# Registry path for local development
REGISTRY_PATH = registry.opentofu.org/istr/gopass/$(VERSION)/$(OS_ARCH)

.PHONY: help build install install-tofu install-tf clean test fmt lint docs

help:
	@echo "terraform-provider-gopass"
	@echo ""
	@echo "Build targets:"
	@echo "  make build        Build the provider binary"
	@echo "  make install      Install to both OpenTofu and Terraform plugin dirs"
	@echo "  make install-tofu Install to OpenTofu plugin directory only"
	@echo "  make install-tf   Install to Terraform plugin directory only"
	@echo ""
	@echo "Development targets:"
	@echo "  make test         Run tests"
	@echo "  make fmt          Format Go code"
	@echo "  make lint         Run linter"
	@echo "  make clean        Remove built binaries"
	@echo ""
	@echo "Other:"
	@echo "  make deps         Download dependencies"
	@echo "  make docs         Generate documentation"

# Build
build:
	go build -ldflags="-X main.version=$(VERSION)" -o $(BINARY_NAME)

# Install for OpenTofu
install-tofu: build
	@mkdir -p $(TOFU_PLUGIN_DIR)/$(REGISTRY_PATH)
	cp $(BINARY_NAME) $(TOFU_PLUGIN_DIR)/$(REGISTRY_PATH)/$(BINARY_NAME)
	@echo "Installed to $(TOFU_PLUGIN_DIR)/$(REGISTRY_PATH)/"

# Install for Terraform
install-tf: build
	@mkdir -p $(TF_PLUGIN_DIR)/$(REGISTRY_PATH)
	cp $(BINARY_NAME) $(TF_PLUGIN_DIR)/$(REGISTRY_PATH)/$(BINARY_NAME)
	@echo "Installed to $(TF_PLUGIN_DIR)/$(REGISTRY_PATH)/"

# Install for both
install: install-tofu install-tf

# Development
deps:
	go mod download
	go mod tidy

fmt:
	go fmt ./...

lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

test:
	go test -v ./...

# Test with actual gopass (requires gopass setup)
test-integration:
	TF_ACC=1 go test -v ./... -run TestAcc

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

# Generate provider documentation (requires tfplugindocs)
docs:
	@which tfplugindocs > /dev/null || (echo "Installing tfplugindocs..." && go install github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@latest)
	tfplugindocs generate

# Release build (cross-compile)
release:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)_$(VERSION)_linux_amd64
	GOOS=linux GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)_$(VERSION)_linux_arm64
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)_$(VERSION)_darwin_amd64
	GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)_$(VERSION)_darwin_arm64
