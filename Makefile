# Makefile for QUICS project

.PHONY: all server client clean test vet fmt install

# Version information
VERSION := 0.1
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE) -X main.GitCommit=$(GIT_COMMIT)"

# Directories
BINDIR := bin
SERVER_BINARY := $(BINDIR)/quicsd
CLIENT_BINARY := $(BINDIR)/quicsc

# Default target
all: server client

# Build server
server:
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $(SERVER_BINARY) ./cmd/server

# Build client  
client:
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $(CLIENT_BINARY) ./cmd/client

# Build both server and client
both: server client

# Run tests
test:
	go test ./...

# Run vet
vet:
	go vet ./...

# Format code
fmt:
	gofmt -w .

# Clean build artifacts
clean:
	rm -rf $(BINDIR) quicsd quicsc server client *.log
	go clean -cache

# Install locally (not recommended for production)
install: server client
	@echo "Note: For production use, create packages via rpm or debian targets"
	@echo "Server: $(SERVER_BINARY)"
	@echo "Client: $(CLIENT_BINARY)"

# Create RPM package
rpm: server client
	@mkdir -p rpm/BUILD rpm/RPMS rpm/SOURCES rpm/SPECS rpm/SRPMS
	cp rpm/quics.spec rpm/SPECS/
	rpmbuild --define "_topdir $(CURDIR)/rpm" -bb rpm/SPECS/quics.spec
	@echo "RPM created in rpm/RPMS/"

# Create Debian package
deb: server client
	@echo "Debian packaging not yet implemented"
	@echo "Run: dpkg-buildpackage -us -uc -b"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          : Build server and client (default)"
	@echo "  server       : Build server only"
	@echo "  client       : Build client only"
	@echo "  both         : Build server and client"
	@echo "  test         : Run tests"
	@echo "  vet          : Run go vet"
	@echo "  fmt          : Format code with gofmt"
	@echo "  clean        : Remove build artifacts"
	@echo "  install      : Build and show installation info"
	@echo "  rpm          : Build RPM package"
	@echo "  deb          : Build Debian package (not implemented)"
	@echo "  help         : Show this help"