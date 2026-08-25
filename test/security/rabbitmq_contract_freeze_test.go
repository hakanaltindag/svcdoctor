package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// RabbitMQ contract-freeze guard.
//
// # Why a negative guard exists at all
//
// Phase 8.1 froze the RabbitMQ BASIC contract in ADRs 0067 to 0070 and wrote no
// RabbitMQ code. That is ADR 0054's ordering — an owner before a producer — and
// it has a failure mode this file exists to catch: a contract nobody reads.
//
// The precedent is `kafka_production_reachability_test.go`, which until Phase
// 6.1c asserted that `internal/adapter/kafka` had zero production importers and
// that no `DiagnoseKafka` existed. That negative stopped the first attempt at
// Kafka composition, which would have let a rejected credential arrive as
// `findings: []`, `status: OK`, exit 0. This file is the same shape for
// RabbitMQ, and it is expected to be **turned around rather than deleted** when
// the implementation phase lands: where it now says *nothing exists*, it will
// say *exactly this exists and exactly these rules explain it*.
//
// # What it can and cannot prove
//
// These are static guards over the tree and over the documents. They prove that
// the frozen decisions have not been quietly pre-empted, and that the compat
// document has not started claiming a protocol the binary cannot speak. They
// prove nothing about behaviour, because there is no behaviour yet.

// rabbitmqProductionPackages are the packages that must not exist while the
// contract is frozen and unimplemented.
var rabbitmqProductionPackages = []string{
	"internal/adapter/rabbitmq",
	"internal/adapter/rabbitmq/wire",
	"internal/diagnosis/rabbitmq",
	"internal/service/rabbitmq",
}

// TestRabbitMQIsFrozenAndUnimplemented is the central negative.
//
// A package appearing here before the four ADRs are read is the defect: the
// contract exists precisely so that an implementer makes no semantic decision,
// and code arriving first is how that guarantee is lost.
func TestRabbitMQIsFrozenAndUnimplemented(t *testing.T) {
	root := repositoryRoot(t)
	for _, pkg := range rabbitmqProductionPackages {
		if _, err := os.Stat(filepath.Join(root, pkg)); err == nil {
			t.Errorf("%s exists, but the RabbitMQ contract is frozen and unimplemented.\n\n"+
				"If the implementation phase has started, this file is to be turned "+
				"around into the positive closure guard ADR 0054 section 5 asks for — "+
				"not deleted. Read ADRs 0067 to 0070 first.", pkg)
		}
	}
}

// TestNoRabbitMQCompositionRootExists guards the other half of the same rule.
//
// A composition root is what makes an adapter product-reachable, so its absence
// is what makes the absent owner safe.
func TestNoRabbitMQCompositionRootExists(t *testing.T) {
	root := repositoryRoot(t)
	for _, dir := range []string{"internal/app", "internal/cli"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(root, dir, entry.Name())
			source, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if strings.Contains(string(source), "DiagnoseRabbitMQ") {
				t.Errorf("%s names DiagnoseRabbitMQ, but no RabbitMQ adapter exists.\n\n"+
					"A composition root is what makes an adapter product-reachable "+
					"(ADR 0054).", path)
			}
		}
	}
}

// TestTheRabbitMQContractRecordsExist proves the freeze is written down.
//
// The negative above is only safe while the positive it defers to is readable.
// A deleted or renamed record would leave a guard forbidding work with no
// document explaining what to build instead.
func TestTheRabbitMQContractRecordsExist(t *testing.T) {
	records := map[string]string{
		"docs/decisions/0067-rabbitmq-basic-journey-and-terminal-boundary.md":         "Connection.Open-Ok",
		"docs/decisions/0068-rabbitmq-authentication-and-credential-authority.md":     "authentication_failure_close",
		"docs/decisions/0069-rabbitmq-vhost-authorization-and-close-normalization.md": "UNSPECIFIED_TRUNCATED",
		"docs/decisions/0070-rabbitmq-tune-contract-and-wire-bounds.md":               "channel_max",
	}
	root := repositoryRoot(t)
	for name, mustMention := range records {
		source, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // a repository path this test built.
		if err != nil {
			t.Errorf("%s is missing: the freeze guard forbids work that this record "+
				"is supposed to describe: %v", name, err)
			continue
		}
		text := string(source)
		if !strings.Contains(text, "Accepted in Phase 8.1") {
			t.Errorf("%s no longer records itself as accepted in Phase 8.1", name)
		}
		if !strings.Contains(text, mustMention) {
			t.Errorf("%s no longer mentions %q, which is one of the things it exists "+
				"to freeze", name, mustMention)
		}
	}
}

// TestTheCompatibilityDocumentDeniesRabbitMQ is the truthfulness half.
//
// svcdoctor cannot speak AMQP 0-9-1. A compatibility row that stopped saying so
// would be the exact defect `internal/cli/docsclaims_test.go` exists to catch,
// for a protocol that guard does not know about yet.
func TestTheCompatibilityDocumentDeniesRabbitMQ(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "docs/COMPATIBILITY.md")) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("read docs/COMPATIBILITY.md: %v", err)
	}
	text := string(source)

	if !strings.Contains(text, "NOT IMPLEMENTED") {
		t.Error("docs/COMPATIBILITY.md no longer records RabbitMQ as NOT IMPLEMENTED")
	}

	// Every RabbitMQ-family row stays at Level 0 until svcdoctor itself completes
	// the journey against a real instance. A protocol study run by a scratch
	// client proves what the broker does and nothing about what svcdoctor does.
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		if !strings.Contains(lower, "rabbitmq") && !strings.Contains(lower, "lavinmq") &&
			!strings.Contains(lower, "cloudamqp") {
			continue
		}
		if strings.Contains(line, "TESTED BASIC") || strings.Contains(line, "SUPPORTED BASIC") {
			t.Errorf("docs/COMPATIBILITY.md claims real evidence for an AMQP row while "+
				"svcdoctor has no AMQP implementation.\n\nrow: %s", line)
		}
	}
}

// --- the one thing Phase 8.1 did implement ----------------------------------

// TestResourceLimitReachedIsNamedAndDistinct pins the single production change.
//
// The class was added for a condition **two** services produce, which is the bar
// `internal/adapter/postgres/establish.go` had written down while declining to
// create one. Naming it here as well as in the domain package is deliberate: the
// domain test proves the vocabulary is coherent, and this one proves the class
// survives as a cross-service fact rather than a PostgreSQL detail.
func TestResourceLimitReachedIsNamedAndDistinct(t *testing.T) {
	if got := domain.FailureResourceLimitReached.String(); got != "RESOURCE_LIMIT_REACHED" {
		t.Errorf("class name = %q, want RESOURCE_LIMIT_REACHED", got)
	}
	for _, other := range []domain.FailureClass{
		domain.FailureAuthzDenied,
		domain.FailureAuthzNotPermitted,
		domain.FailureResourceNotFound,
		domain.FailureProtocolUnexpectedResponse,
	} {
		if domain.FailureResourceLimitReached == other {
			t.Errorf("a named capacity ceiling collapsed into %s", other)
		}
	}
}

// TestPostgresConnectionLimitUsesTheSharedClass proves the migration landed.
//
// Two services classifying the identical condition differently would be worse
// than either choice alone, which is why ADR 0069 section 6.1 made the migration
// part of the decision rather than a follow-up. This asserts it through the
// package's exported surface, so it fails if the mapping is reverted.
func TestPostgresConnectionLimitUsesTheSharedClass(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "internal/adapter/postgres/establish.go")) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("read establish.go: %v", err)
	}
	text := string(source)
	if !strings.Contains(text, `case "53300":`) ||
		!strings.Contains(text, "domain.FailureResourceLimitReached") {
		t.Error("PostgreSQL SQLSTATE 53300 no longer maps to RESOURCE_LIMIT_REACHED.\n\n" +
			"ADR 0069 section 6.1 makes this pairing part of the decision: reverting it " +
			"leaves two services classifying one condition differently.")
	}

	// And the package still exists to be classified against, which keeps this
	// guard from passing vacuously if the file is moved.
	if postgres.StepSession == "" {
		t.Error("internal/adapter/postgres no longer exposes StepSession")
	}
}
