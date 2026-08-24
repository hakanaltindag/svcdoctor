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

.PHONY: help fmt fmt-check test vet lint build check clean image image-dev

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

image: ## Build the official OCI image (requires a semver-tagged, clean HEAD; never pushes)
	@./scripts/build-image.sh

image-dev: ## Build a development OCI image tagged sha-<commit> (not reproducible, not official)
	@./scripts/build-image.sh --dev --platform linux/$(shell go env GOARCH)

clean: ## Remove build output
	$(GO) clean
	rm -rf bin dist

# --- Kafka integration validation (Phase 3 gate) ----------------------------
#
# Deliberately not part of `check`: it needs Docker and takes minutes, while the
# ordinary gate must stay fast and hermetic. See test/integration/kafka/README.md.

KAFKA_ENV := test/integration/kafka/env
KAFKA_COMPOSE := docker compose -f $(KAFKA_ENV)/compose-sasl.yaml

.PHONY: kafka-up kafka-down kafka-test kafka-scram-users integration-kafka

kafka-up: ## Start the 3-broker Kafka validation cluster
	@$(KAFKA_ENV)/gen-certs.sh
	# --force-recreate, because gen-certs.sh above rewrote the CA and the broker
	# keystore. Kafka reads its keystore once at JVM start, so a broker left
	# running from an earlier attempt keeps serving a certificate the freshly
	# generated CA did not sign — and every handshake fails with
	# TLS_UNKNOWN_AUTHORITY while the mounted CA file looks perfectly correct.
	#
	# It is easy to reach: `integration-kafka` chains up, test and down, so a
	# failing test aborts the chain before `kafka-down` runs and leaves the old
	# brokers up for the next attempt. That produced an afternoon of "SCRAM is
	# broken" during Phase 6.2 when SCRAM was fine. The composition suite already
	# carried a comment about this exact hazard; this removes it instead.
	@$(KAFKA_COMPOSE) up -d --force-recreate
	@printf 'waiting for three registered brokers'
	@for i in $$(seq 1 60); do \
		n=$$(docker exec svcd-sasl-1 /opt/kafka/bin/kafka-broker-api-versions.sh \
			--bootstrap-server broker-1:9094 2>/dev/null | grep -c 'id: ' || true); \
		if [ "$$n" = "3" ]; then printf ' ready\n'; exit 0; fi; \
		printf '.'; sleep 1; \
	done; printf '\ncluster did not become ready\n'; exit 1
	@$(MAKE) --no-print-directory kafka-scram-users

# SCRAM credentials cannot live in jaas.conf: KRaft keeps SCRAM verifiers in the
# metadata log, so they are created after the quorum is up. The INTERNAL
# PLAINTEXT listener is used because it needs no credential to reach — which is
# the point, since these commands are creating the first one.
#
# Creation is followed by a propagation wait, and that is not defensive padding.
# kafka-configs returns as soon as the record is committed to the metadata log,
# but each broker's ScramPublisher applies it asynchronously — so a suite that
# starts immediately authenticates against a broker that has not yet loaded the
# verifier and gets a failure indistinguishable from a wrong password. Measured:
# the SCRAM tests passed when run by hand seconds later and failed under
# `make integration-kafka`, which has no such gap.
#
# The second principal deliberately contains a comma and an equals sign. RFC 5802
# requires them to be sent as =2C and =3D, PostgreSQL never needed that escaping
# because it sends an empty username, and Phase 6.2a found the code did not
# exist. This is the fixture that proves it works against a real broker rather
# than only against a vector.
kafka-scram-users: ## Create the SCRAM-SHA-256 principals the suite authenticates as
	@for user in 'svcdoctor-scram:svcdoctor-scram-canary' 'a,b=c:escaped-name-canary'; do \
		name=$${user%%:*}; pass=$${user##*:}; \
		docker exec svcd-sasl-1 /opt/kafka/bin/kafka-configs.sh \
			--bootstrap-server broker-1:9094 \
			--alter --add-config "SCRAM-SHA-256=[iterations=4096,password=$$pass]" \
			--entity-type users --entity-name "$$name" >/dev/null \
			|| { printf 'could not create SCRAM user %s\n' "$$name"; exit 1; }; \
	done
	@printf 'waiting for scram credentials on every broker'
	@for i in $$(seq 1 60); do \
		ok=1; \
		for b in 1 2 3; do \
			docker exec svcd-sasl-$$b /opt/kafka/bin/kafka-configs.sh \
				--bootstrap-server broker-$$b:9094 --describe --entity-type users \
				--entity-name svcdoctor-scram 2>/dev/null | grep -q 'SCRAM-SHA-256' || ok=0; \
		done; \
		if [ "$$ok" = "1" ]; then printf ' ready\n'; exit 0; fi; \
		printf '.'; sleep 1; \
	done; printf '\nscram credentials did not propagate\n'; exit 1
	# The describe above proves the record reached every broker's config view.
	# It does **not** prove the SASL server can use it: each broker's
	# ScramPublisher applies the record to its credential cache asynchronously,
	# and there is no supported command that reports when that has happened.
	#
	# A settle is therefore the honest mechanism, and it is bounded by
	# measurement rather than by taste: the window from kafka-up returning to the
	# first successful SCRAM authentication was measured at 2 seconds, and this
	# waits 10. Without it the suite authenticates against a broker that has the
	# credential written but not yet loaded, and the failure is indistinguishable
	# from a wrong password — which is precisely how it presented.
	@sleep 10
	@printf 'scram credentials ready\n'

kafka-down: ## Stop the validation cluster and delete its volumes
	@$(KAFKA_COMPOSE) down -v --remove-orphans

kafka-test: ## Run the Kafka integration suite against a running cluster
	$(GO) test -tags integration -count=1 -timeout 30m ./test/integration/kafka/...

integration-kafka: kafka-up kafka-test kafka-down ## Full Kafka validation gate

# --- PostgreSQL integration validation (Phase 4 gate) -----------------------
#
# Deliberately not part of `check`, for the reason the Kafka gate is not: it
# needs Docker, while the ordinary gate must stay fast and hermetic.
# See test/integration/postgres/README.md.

PG_ENV := test/integration/postgres/env
PG_COMPOSE := docker compose -f $(PG_ENV)/compose.yaml
# Read from the compose file rather than repeated, so the diagnostics below and
# gen-certs.sh cannot disagree with what actually runs.
PG_IMAGE := $(shell awk '/^[[:space:]]*image:[[:space:]]*/ {print $$2; exit}' $(PG_ENV)/compose.yaml)

.PHONY: postgres-up postgres-down postgres-test integration-postgres

# `pg_isready` is a protocol-level readiness question and stays: it is the only
# check that distinguishes "the container is running" from "the server will
# answer". The v0.3.1 release failed here, and the reason the failure cost a
# release tag is that the message said only "servers did not become ready" —
# which is a symptom. The server had exited at startup over its TLS key
# ownership, and nothing printed said so.
#
# So on failure the fixture now says why. Bounded output, both services, and the
# original non-zero exit is preserved: diagnostics explain a failure, they never
# convert one into success.
postgres-up: ## Start the PostgreSQL validation server
	@$(PG_ENV)/gen-certs.sh
	@$(PG_COMPOSE) up -d
	@printf 'waiting for postgres'
	@for i in $$(seq 1 60); do \
		if docker exec svcd-pg pg_isready -q -U app -d appdb 2>/dev/null \
			&& docker exec svcd-pg-plaintext pg_isready -q -U app -d appdb 2>/dev/null; then \
			printf ' ready\n'; exit 0; fi; \
		printf '.'; sleep 1; \
	done; \
	printf '\nservers did not become ready\n'; \
	printf '\n--- container state ---\n'; \
	$(PG_COMPOSE) ps || true; \
	for svc in postgres postgres-plaintext; do \
		printf '\n--- %s (last 40 lines) ---\n' "$$svc"; \
		$(PG_COMPOSE) logs --tail=40 --no-color "$$svc" 2>&1 || true; \
	done; \
	printf '\n--- TLS key as the container sees it ---\n'; \
	docker run --rm -v "$$PWD/$(PG_ENV)/certs:/c" $(PG_IMAGE) \
		sh -c 'stat -c "server.key uid=%u gid=%g mode=%a" /c/server.key; \
		       echo "postgres uid=$$(id -u postgres) gid=$$(id -g postgres)"' 2>&1 || true; \
	exit 1

postgres-down: ## Stop the validation server and delete its volume
	@$(PG_COMPOSE) down -v --remove-orphans

postgres-test: ## Run the PostgreSQL integration suite against a running server
	$(GO) test -tags integration -count=1 -timeout 10m ./test/integration/postgres/...

integration-postgres: postgres-up postgres-test postgres-down ## Full PostgreSQL validation gate

# --- Redpanda integration validation (Phase 7.0b gate) ----------------------
#
# Deliberately not part of `check`, for the reason the other two are not: it
# needs Docker. It is also deliberately **not** run concurrently with the Kafka
# gate — Phase 7.0 observed one unexplained Kafka failure while a Redpanda
# instance was competing for the same cores, and the closure evidence for both
# is only meaningful if each ran alone.
#
# The version is pinned in env/compose.yaml. ADR 0061's evidence is about
# Redpanda v25.1.9 specifically, whose SCRAM salt is 130 bytes.

RP_ENV := test/integration/redpanda/env
RP_COMPOSE := docker compose -f $(RP_ENV)/compose.yaml

.PHONY: redpanda-up redpanda-down redpanda-test redpanda-users integration-redpanda

redpanda-up: ## Start the Redpanda validation broker
	@$(RP_ENV)/gen-certs.sh
	@$(RP_COMPOSE) up -d --force-recreate
	@printf 'waiting for redpanda'
	@for i in $$(seq 1 90); do \
		if docker exec svcd-redpanda curl -sf http://localhost:9644/v1/status/ready \
			>/dev/null 2>&1; then printf ' ready\n'; exit 0; fi; \
		printf '.'; sleep 2; \
	done; printf '\nredpanda did not become ready\n'; \
	docker logs svcd-redpanda 2>&1 | tail -20; exit 1
	@$(MAKE) --no-print-directory redpanda-users

# The first principal cannot be created over the Kafka API, because SASL is
# already on and there is no credential yet to authenticate the request with.
# Redpanda's admin API is not SASL-gated, which is the documented bootstrap
# path and the only one available here.
#
# Two principals: the SCRAM one this phase exists to validate, and a second used
# for the PLAIN scenarios. Both are fixture-only values on a loopback container.
redpanda-users: ## Create the validation principals
	@for u in 'svcdoctor:svcdoctor-redpanda-canary' 'plainuser:plainuser-redpanda-canary'; do \
		name=$${u%%:*}; pass=$${u##*:}; \
		docker exec svcd-redpanda curl -sf -X POST http://localhost:9644/v1/security/users \
			-H 'Content-Type: application/json' \
			-d "{\"username\":\"$$name\",\"password\":\"$$pass\",\"algorithm\":\"SCRAM-SHA-256\"}" \
			>/dev/null || { printf 'could not create principal %s\n' "$$name"; exit 1; }; \
	done
	@printf 'waiting for principals'
	@for i in $$(seq 1 30); do \
		if docker exec svcd-redpanda curl -sf http://localhost:9644/v1/security/users \
			2>/dev/null | grep -q svcdoctor; then \
			printf ' ready\n'; exit 0; fi; \
		printf '.'; sleep 1; \
	done; printf '\nprincipals did not appear\n'; exit 1

redpanda-down: ## Stop the validation broker and delete its volumes
	@$(RP_COMPOSE) down -v --remove-orphans

redpanda-test: ## Run the Redpanda integration suite against a running broker
	$(GO) test -tags integration -count=1 -timeout 15m ./test/integration/redpanda/...

integration-redpanda: redpanda-up redpanda-test redpanda-down ## Full Redpanda validation gate
