# svcdoctor local quality gates.
#
# `make check` is the normal pre-commit gate and mirrors CI.
#
# The repository currently contains no Go packages. Gates that require packages
# report SKIPPED and activate automatically once Phase 1 adds the first package.
# No placeholder Go code exists to make these gates artificially green.

GO                     ?= go
GOLANGCI_LINT          ?= golangci-lint
GOLANGCI_LINT_VERSION  ?= v2.13.1
BUILD_ENV              := CGO_ENABLED=0

# Empty until the first Go package exists. Evaluated once, at parse time.
GOPKGS := $(shell $(GO) list ./... 2>/dev/null)

NO_PKGS_MSG = no Go packages yet; gate activates with the first package (Phase 1)

.PHONY: help fmt fmt-check test vet lint build check clean

help: ## Show available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  %-10s %s\n", $$1, $$2}'

fmt: ## Format Go sources in place
	gofmt -w .

fmt-check: ## Verify Go sources are gofmt-formatted (never modifies files)
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-formatted:"; echo "$$unformatted"; exit 1; \
	fi
	@echo "fmt-check: OK"

ifeq ($(strip $(GOPKGS)),)

test:
	@echo "test:      SKIPPED - $(NO_PKGS_MSG)"

vet:
	@echo "vet:       SKIPPED - $(NO_PKGS_MSG)"

lint:
	@echo "lint:      SKIPPED - $(NO_PKGS_MSG)"

build:
	@echo "build:     SKIPPED - $(NO_PKGS_MSG)"

else

test: ## Run tests
	$(GO) test ./...

vet: ## Run go vet
	$(GO) vet ./...

lint: ## Run golangci-lint
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "golangci-lint not found; install $(GOLANGCI_LINT_VERSION)"; exit 1; }
	@$(GOLANGCI_LINT) version 2>/dev/null | grep -q 'version 2\.' || { \
		echo "golangci-lint $(GOLANGCI_LINT_VERSION) required; .golangci.yml uses the v2 config format"; \
		echo "found: $$($(GOLANGCI_LINT) version 2>&1 | head -1)"; exit 1; }
	$(GOLANGCI_LINT) run ./...

build: ## Build the CLI (CGO_ENABLED=0)
	$(BUILD_ENV) $(GO) build ./...

endif

check: fmt-check test vet lint build ## Run the full local quality gate

clean: ## Remove build output
	$(GO) clean
	rm -rf bin dist
