package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/redis"
)

// The Phase 9.1A configuration matrix.
//
// Every case here is a document this package must accept or refuse, and the
// refusals are the point: a configuration parser's value is entirely in what it
// declines to guess. MT-C identifiers refer to the Phase 9.0 test matrix in
// docs/validation/MULTI_TARGET_PHASE90_CONTRACT_STUDY.md section 6.1.

// testRegistry builds the production registry.
func testRegistry(t testing.TB) *config.Registry {
	t.Helper()
	registry, err := config.NewRegistry(
		postgres.Factory{}, kafka.Factory{}, redis.Factory{}, rabbitmq.Factory{},
	)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return registry
}

// load is the shorthand every case uses.
func load(t testing.TB, doc string) (config.Config, error) {
	t.Helper()
	return config.Load([]byte(doc), "services.yaml", testRegistry(t))
}

// validFourService is the reference document: one target per service, every
// generic field exercised, and all four credential shapes.
const validFourService = `
version: 1

run:
  concurrency: 4
  timeout: 10m

targets:
  - id: orders-db
    type: postgres
    host: orders-db.internal.example.com
    port: 5432
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: /etc/ssl/internal-ca.pem
      server_name: orders-db.internal.example.com
    credentials:
      username: svcdoctor
      password:
        env: ORDERS_DB_PASSWORD
    config:
      database: orders

  - id: events-bootstrap
    type: kafka
    host: kafka-1.internal.example.com
    port: 9093
    credentials:
      username: svcdoctor
      password:
        file: /run/secrets/kafka
    config:
      sasl_mechanism: SCRAM-SHA-256

  - id: session-cache
    type: redis
    host: redis.internal.example.com

  - id: task-queue
    type: rabbitmq
    host: rabbit.internal.example.com
    port: 5671
    credentials:
      username: svcdoctor
      password:
        env: RABBITMQ_PASSWORD
    config:
      vhost: /production
`

// TestMTC01AValidFourServiceFileLoads is MT-C01.
func TestMTC01AValidFourServiceFileLoads(t *testing.T) {
	cfg, err := load(t, validFourService)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Version != config.Version {
		t.Errorf("Version = %d, want %d", cfg.Version, config.Version)
	}
	if got, want := len(cfg.Targets), 4; got != want {
		t.Fatalf("len(Targets) = %d, want %d", got, want)
	}
	if got, want := cfg.Run.Concurrency, 4; got != want {
		t.Errorf("Run.Concurrency = %d, want %d", got, want)
	}
	if got, want := cfg.Run.Timeout, 10*time.Minute; got != want {
		t.Errorf("Run.Timeout = %s, want %s", got, want)
	}

	// Each service's own configuration is a concrete type, not a map.
	if _, ok := cfg.Targets[0].Config.(postgres.Config); !ok {
		t.Errorf("target 0 config is %T, want postgres.Config", cfg.Targets[0].Config)
	}
	if _, ok := cfg.Targets[1].Config.(kafka.Config); !ok {
		t.Errorf("target 1 config is %T, want kafka.Config", cfg.Targets[1].Config)
	}
	if _, ok := cfg.Targets[2].Config.(redis.Config); !ok {
		t.Errorf("target 2 config is %T, want redis.Config", cfg.Targets[2].Config)
	}
	if _, ok := cfg.Targets[3].Config.(rabbitmq.Config); !ok {
		t.Errorf("target 3 config is %T, want rabbitmq.Config", cfg.Targets[3].Config)
	}

	// Defaults are the leaf commands', so a target written with no budgets
	// behaves exactly as the equivalent single-target invocation.
	redisTarget := cfg.Targets[2]
	if got, want := redisTarget.Port, uint16(redis.DefaultPort); got != want {
		t.Errorf("redis port = %d, want the service default %d", got, want)
	}
	if got, want := redisTarget.Timeout, config.DefaultTargetTimeout; got != want {
		t.Errorf("redis timeout = %s, want %s", got, want)
	}
	if got, want := redisTarget.StepTimeout, config.DefaultStepTimeout; got != want {
		t.Errorf("redis step timeout = %s, want %s", got, want)
	}
	if !redisTarget.Credentials.Password.IsZero() {
		t.Error("a target with no credentials block must carry no reference")
	}

	// The credential references are references, and each names one source.
	if got, want := cfg.Targets[0].Credentials.Password.Kind(), config.SourceEnv; got != want {
		t.Errorf("orders-db source = %s, want %s", got, want)
	}
	if got, want := cfg.Targets[0].Credentials.Password.Name(), "ORDERS_DB_PASSWORD"; got != want {
		t.Errorf("orders-db name = %q, want %q", got, want)
	}
	if got, want := cfg.Targets[1].Credentials.Password.Kind(), config.SourceFile; got != want {
		t.Errorf("events source = %s, want %s", got, want)
	}

	// Service-owned values survive validation.
	if got, want := cfg.Targets[0].Config.(postgres.Config).Database, "orders"; got != want {
		t.Errorf("database = %q, want %q", got, want)
	}
	if got, want := cfg.Targets[3].Config.(rabbitmq.Config).VHostOrDefault(), "/production"; got != want {
		t.Errorf("vhost = %q, want %q", got, want)
	}
}

// TestDeclaredOrderIsPreservedByTheLoader is MT-C17.
//
// The order in the file is the order in the configuration, and it survives
// validation, service dispatch and every default being filled in. ADR 0073
// section 6 makes this the aggregate report's order, so it is pinned here where
// the slice is built rather than only where it is later rendered.
func TestDeclaredOrderIsPreservedByTheLoader(t *testing.T) {
	cfg, err := load(t, validFourService)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := []string{"orders-db", "events-bootstrap", "session-cache", "task-queue"}
	if got := cfg.TargetIDs(); !equalStrings(got, want) {
		t.Errorf("TargetIDs() = %v, want %v (declared order, never sorted)", got, want)
	}

	// Sorted order would be a different answer, which is what makes this test
	// able to fail if someone adds a sort.
	sorted := []string{"events-bootstrap", "orders-db", "session-cache", "task-queue"}
	if equalStrings(cfg.TargetIDs(), sorted) {
		t.Error("targets came back in sorted order; declared order is the contract")
	}
}

// TestDeclaredOrderSurvivesEveryPermutation proves the order comes from the
// input rather than from anything derived.
func TestDeclaredOrderSurvivesEveryPermutation(t *testing.T) {
	ids := []string{"zulu", "alpha", "mike", "bravo"}
	var b strings.Builder
	b.WriteString("version: 1\ntargets:\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "  - id: %s\n    type: redis\n    host: h.example.com\n", id)
	}

	cfg, err := load(t, b.String())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.TargetIDs(); !equalStrings(got, ids) {
		t.Errorf("TargetIDs() = %v, want %v", got, ids)
	}
}

func TestMTC02DuplicateTargetID(t *testing.T) {
	_, err := load(t, `
version: 1
targets:
  - id: orders-db
    type: redis
    host: a.example.com
  - id: orders-db
    type: redis
    host: b.example.com
`)
	assertCategory(t, err, config.CategoryDuplicateID)
	// Both occurrences are locatable: the message names the earlier index.
	if !strings.Contains(err.Error(), "targets[0]") {
		t.Errorf("err = %v, want the first occurrence named", err)
	}
}

func TestMTC03UnknownServiceType(t *testing.T) {
	_, err := load(t, `
version: 1
targets:
  - id: a
    type: mysql
    host: a.example.com
`)
	assertCategory(t, err, config.CategoryUnsupportedService)
	// The supported list is what distinguishes a typo from a missing service.
	for _, kind := range []string{"postgres", "kafka", "redis", "rabbitmq"} {
		if !strings.Contains(err.Error(), kind) {
			t.Errorf("err = %v, want it to list %q", err, kind)
		}
	}
}

// TestMTC04AndC05UnknownFieldIsRejectedAtEveryLevel is MT-C04.
//
// Every level, because a strictness that holds at the root and not inside a
// service configuration is a strictness an operator cannot rely on.
func TestMTC04AndC05UnknownFieldIsRejectedAtEveryLevel(t *testing.T) {
	tests := []struct {
		level string
		doc   string
	}{
		{"root", `
version: 1
bogus: x
targets:
  - id: a
    type: redis
    host: a.example.com
`},
		{"run section", `
version: 1
run:
  bogus: x
targets:
  - id: a
    type: redis
    host: a.example.com
`},
		{"target envelope", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    bogus: x
`},
		{"tls block", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    tls:
      bogus: x
`},
		{"credentials block", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    credentials:
      username: u
      bogus: x
`},
		{"credential reference", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    credentials:
      username: u
      password:
        env: E
        bogus: x
`},
		{"service config", `
version: 1
targets:
  - id: a
    type: postgres
    host: a.example.com
    credentials:
      username: u
    config:
      database: d
      bogus: x
`},
		{"service config of a service with no fields", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    config:
      db: 0
`},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			if _, err := load(t, tt.doc); err == nil {
				t.Fatal("an unknown field was accepted; unknown fields must fail closed")
			}
		})
	}
}

// TestMTC14DuplicateYAMLKeyIsRejectedAtEveryLevel is MT-C09.
//
// Last-wins is the behaviour `encoding/json` has and this configuration must not:
// a silently discarded credential reference is the config-file form of a
// truncated secret.
func TestMTC14DuplicateYAMLKeyIsRejectedAtEveryLevel(t *testing.T) {
	tests := []struct {
		level string
		doc   string
	}{
		{"root", "version: 1\nversion: 1\ntargets: []\n"},
		{"run", `
version: 1
run:
  concurrency: 1
  concurrency: 2
targets:
  - id: a
    type: redis
    host: a.example.com
`},
		{"target", `
version: 1
targets:
  - id: a
    id: b
    type: redis
    host: a.example.com
`},
		{"service config", `
version: 1
targets:
  - id: a
    type: postgres
    host: a.example.com
    credentials:
      username: u
    config:
      database: one
      database: two
`},
		{"credential reference", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    credentials:
      username: u
      password:
        env: ONE
        env: TWO
`},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			_, err := load(t, tt.doc)
			if err == nil {
				t.Fatal("a duplicate key was accepted; last-wins is not the contract")
			}
			if !strings.Contains(err.Error(), "already defined") {
				t.Errorf("err = %v, want a duplicate-key refusal", err)
			}
		})
	}
}

func TestMTC13MalformedYAML(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"tab indentation", "version: 1\ntargets:\n\t- id: a\n"},
		{"unclosed flow mapping", "version: 1\nrun: {concurrency: 1\n"},
		{"unterminated quote", "version: 1\ntargets:\n  - id: \"a\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			assertCategory(t, err, config.CategorySyntax)
		})
	}
}

func TestAnEmptyDocumentIsRefusedWithItsOwnMessage(t *testing.T) {
	for _, doc := range []string{"", "\n\n", "# only a comment\n"} {
		_, err := load(t, doc)
		assertCategory(t, err, config.CategorySyntax)
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("doc %q: err = %v, want an emptiness refusal", doc, err)
		}
	}
}

// TestMTC20OnlyOneDocumentIsAccepted covers ADR 0071 section 8's document rule.
func TestMTC20OnlyOneDocumentIsAccepted(t *testing.T) {
	const oneTarget = `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
`
	t.Run("a leading marker is still one document", func(t *testing.T) {
		if _, err := load(t, "---"+oneTarget); err != nil {
			t.Errorf("a leading --- must be accepted: %v", err)
		}
	})
	t.Run("a trailing comment is still one document", func(t *testing.T) {
		if _, err := load(t, oneTarget+"# trailing note\n"); err != nil {
			t.Errorf("a trailing comment must be accepted: %v", err)
		}
	})
	t.Run("an end marker is still one document", func(t *testing.T) {
		if _, err := load(t, oneTarget+"...\n"); err != nil {
			t.Errorf("a document end marker must be accepted: %v", err)
		}
	})

	multi := []struct{ name, doc string }{
		{"second document", oneTarget + "---\n" + oneTarget},
		{"empty second document", oneTarget + "---\n"},
		{"second document holding only a comment", oneTarget + "---\n# nothing\n"},
	}
	for _, tt := range multi {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			assertCategory(t, err, config.CategorySyntax)
			if !strings.Contains(err.Error(), "more than one YAML document") {
				t.Errorf("err = %v, want a multi-document refusal", err)
			}
		})
	}
}

// TestMTC18MergeKeyIsRejected is MT-C11, and it is the load-bearing one.
//
// Phase 9.0 measured that a merge key decodes silently under KnownFields(true)
// and **without any alias**, so refusing anchors and aliases does not refuse
// merges. Each shape below is a way to reach the same construct.
func TestMTC18MergeKeyIsRejected(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"inline merge into a target", `
version: 1
targets:
  - <<: {type: redis}
    id: a
    host: a.example.com
`},
		{"anchored map merged into a target", `
version: 1
defaults: &d
  type: redis
targets:
  - <<: *d
    id: a
    host: a.example.com
`},
		{"merge inside a service config", `
version: 1
targets:
  - id: a
    type: postgres
    host: a.example.com
    credentials:
      username: u
    config:
      <<: {database: d}
`},
		{"merge inside a credential reference", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    credentials:
      username: u
      password:
        <<: {env: E}
`},
		{"merge inside the tls block", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    tls:
      <<: {mode: disable}
`},
		{"quoted merge key", `
version: 1
targets:
  - "<<": {type: redis}
    id: a
    host: a.example.com
`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			if err == nil {
				t.Fatal("a merge key was accepted")
			}
			// A quoted "<<" is an ordinary string key and is refused as an
			// unknown field rather than as a merge; either refusal is correct,
			// and accepting it is not.
			var configErr *config.Error
			if !errors.As(err, &configErr) {
				t.Fatalf("err = %v, want a config.Error", err)
			}
			switch configErr.Category() {
			case config.CategoryStructure, config.CategoryUnknownField:
			default:
				t.Errorf("category = %s, want a structure or unknown-field refusal",
					configErr.Category())
			}
		})
	}
}

// TestMTC17AnchorAndAliasPolicy is MT-C12.
//
// ADR 0071 section 8.2 refuses both, and the refusal is on the anchor as well as
// on the alias: an anchor with no alias is still a second way to write a target,
// and permitting the definition while refusing the use is a rule nobody can
// predict.
func TestMTC17AnchorAndAliasPolicy(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"anchor with no alias", `
version: 1
targets:
  - &first
    id: a
    type: redis
    host: a.example.com
`},
		{"alias", `
version: 1
targets:
  - &first
    id: a
    type: redis
    host: a.example.com
  - *first
`},
		{"anchored scalar", `
version: 1
targets:
  - id: a
    type: &kind redis
    host: a.example.com
`},
		{"alias inside a credential reference", `
version: 1
name: &n E
targets:
  - id: a
    type: redis
    host: a.example.com
    credentials:
      username: u
      password:
        env: *n
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			assertCategory(t, err, config.CategoryStructure)
		})
	}

	// A scalar whose value merely looks like anchor syntax is data, and the
	// guard is a tree walk rather than a byte search precisely so that this
	// passes.
	t.Run("a scalar containing anchor-like text is data", func(t *testing.T) {
		cfg, err := load(t, `
version: 1
targets:
  - id: a
    type: redis
    host: "&foo-not-an-anchor.example.com"
`)
		if err != nil {
			t.Fatalf("a scalar containing &foo must not be treated as an anchor: %v", err)
		}
		if got, want := cfg.Targets[0].Host, "&foo-not-an-anchor.example.com"; got != want {
			t.Errorf("Host = %q, want %q", got, want)
		}
	})

	t.Run("a scalar containing merge-like text is data", func(t *testing.T) {
		cfg, err := load(t, `
version: 1
targets:
  - id: a
    type: rabbitmq
    host: a.example.com
    step_timeout: 10s
    config:
      vhost: "<<-not-a-merge"
`)
		if err != nil {
			t.Fatalf("a scalar containing << must not be treated as a merge: %v", err)
		}
		if got, want := cfg.Targets[0].Config.(rabbitmq.Config).VHost, "<<-not-a-merge"; got != want {
			t.Errorf("VHost = %q, want %q", got, want)
		}
	})
}

// TestMTC19CustomTagIsRejected is MT-C13.
func TestMTC19CustomTagIsRejected(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"application tag", `
version: 1
targets:
  - id: a
    type: redis
    host: !secret a.example.com
`},
		{"include tag", `
version: 1
targets: !include other.yaml
`},
		{"binary tag", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    credentials:
      username: !!binary aGk=
`},
		{"timestamp tag", `
version: 1
run:
  timeout: 2020-01-01
targets:
  - id: a
    type: redis
    host: a.example.com
`},
		{"float tag", `
version: 1
targets:
  - id: a
    type: redis
    host: a.example.com
    port: 1.5
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			assertCategory(t, err, config.CategoryStructure)
		})
	}
}

// TestMTC15AndC16ConfigVersion is MT-C10, plus every neighbouring case.
func TestMTC15AndC16ConfigVersion(t *testing.T) {
	const targets = `
targets:
  - id: a
    type: redis
    host: a.example.com
`
	tests := []struct {
		name    string
		doc     string
		wantCat config.Category
		wantMsg string
	}{
		{"absent", targets, config.CategoryVersion, "no configuration version"},
		{"zero", "version: 0\n" + targets, config.CategoryVersion, "version 0 is not supported"},
		{"future", "version: 2\n" + targets, config.CategoryVersion, "version 2 is not supported"},
		{"negative", "version: -1\n" + targets, config.CategoryVersion, "not supported"},
		{"string", "version: \"1\"\n" + targets, config.CategoryVersion, "must be the integer"},
		{"null", "version:\n" + targets, config.CategoryVersion, "no configuration version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			assertCategory(t, err, tt.wantCat)
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantMsg)
			}
		})
	}

	t.Run("a duplicate version key is a duplicate, not a version defect", func(t *testing.T) {
		_, err := load(t, "version: 1\nversion: 2\n"+targets)
		assertCategory(t, err, config.CategorySyntax)
	})

	t.Run("version 1 is accepted", func(t *testing.T) {
		if _, err := load(t, "version: 1\n"+targets); err != nil {
			t.Fatalf("version 1 must be accepted: %v", err)
		}
	})
}

// TestAnUnsupportedVersionIsReportedBeforeUnknownFields pins ADR 0071 §4.3's
// ordering.
//
// A version-2 document legitimately holds fields version 1 does not know. If the
// strict decode ran first, the operator would be told about four unknown fields
// instead of the one thing that is actually wrong.
func TestAnUnsupportedVersionIsReportedBeforeUnknownFields(t *testing.T) {
	_, err := load(t, `
version: 2
future_section:
  something: new
targets:
  - id: a
    type: redis
    host: a.example.com
    another_future_field: yes
`)
	assertCategory(t, err, config.CategoryVersion)
	if strings.Contains(err.Error(), "future_section") {
		t.Errorf("err = %v, want the version refusal rather than an unknown-field list", err)
	}
}

// TestMTC24TargetIDGrammar covers ADR 0071 section 5.2 at every boundary.
func TestMTC24TargetIDGrammar(t *testing.T) {
	valid := []string{
		"a", "orders-db", "orders_db", "a1", "1a", "0",
		strings.Repeat("a", config.MaxTargetIDBytes),
	}
	for _, id := range valid {
		t.Run("valid/"+id, func(t *testing.T) {
			if _, err := config.NewTargetID(id); err != nil {
				t.Errorf("NewTargetID(%q) = %v, want it accepted", id, err)
			}
		})
	}

	invalid := []struct{ name, id string }{
		{"empty", ""},
		{"too long", strings.Repeat("a", config.MaxTargetIDBytes+1)},
		{"uppercase", "Orders-DB"},
		{"leading hyphen", "-a"},
		{"trailing hyphen", "a-"},
		{"leading underscore", "_a"},
		{"trailing underscore", "a_"},
		{"dot", "orders.db"},
		{"space", "orders db"},
		{"slash", "orders/db"},
		{"colon", "orders:db"},
		{"non-ascii", "ordërs"},
		{"only a hyphen", "-"},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			if _, err := config.NewTargetID(tt.id); err == nil {
				t.Errorf("NewTargetID(%q) was accepted, want a refusal", tt.id)
			}
		})
	}
}

// TestAnUppercaseIdentifierIsRefusedRatherThanFolded is the case a normalization
// would silently "fix".
func TestAnUppercaseIdentifierIsRefusedRatherThanFolded(t *testing.T) {
	_, err := load(t, `
version: 1
targets:
  - id: Orders-DB
    type: redis
    host: a.example.com
`)
	if err == nil {
		t.Fatal("an uppercase identifier was accepted; it must be refused, not folded")
	}
	if !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("err = %v, want the message to say why", err)
	}
}

func TestAMissingTargetIDIsRefused(t *testing.T) {
	_, err := load(t, `
version: 1
targets:
  - type: redis
    host: a.example.com
`)
	assertCategory(t, err, config.CategoryInvalidField)
	if !strings.Contains(err.Error(), "identifier is required") {
		t.Errorf("err = %v, want a required-identifier refusal", err)
	}
}

// TestMTC23AndC30TargetCountBounds is MT-C15 and MT-C16.
func TestMTC23AndC30TargetCountBounds(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("version: 1\ntargets:\n")
		for i := range n {
			fmt.Fprintf(&b, "  - id: t%d\n    type: redis\n    host: h.example.com\n", i)
		}
		if n == 0 {
			b.WriteString("  []\n")
		}
		return b.String()
	}

	t.Run("zero targets is refused", func(t *testing.T) {
		_, err := config.Load([]byte("version: 1\ntargets: []\n"), "c.yaml", testRegistry(t))
		assertCategory(t, err, config.CategoryInvalidField)
	})
	t.Run("no targets key at all is refused", func(t *testing.T) {
		_, err := config.Load([]byte("version: 1\n"), "c.yaml", testRegistry(t))
		assertCategory(t, err, config.CategoryInvalidField)
	})
	t.Run("one target", func(t *testing.T) {
		if _, err := load(t, build(1)); err != nil {
			t.Fatalf("one target must be accepted: %v", err)
		}
	})
	t.Run("exactly the maximum", func(t *testing.T) {
		cfg, err := load(t, build(config.MaxTargets))
		if err != nil {
			t.Fatalf("%d targets must be accepted: %v", config.MaxTargets, err)
		}
		if got := len(cfg.Targets); got != config.MaxTargets {
			t.Errorf("len(Targets) = %d, want %d", got, config.MaxTargets)
		}
	})
	t.Run("one above the maximum", func(t *testing.T) {
		_, err := load(t, build(config.MaxTargets+1))
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "above the maximum") {
			t.Errorf("err = %v, want the ceiling named", err)
		}
	})
}

// TestMTC22ConfigByteBound is MT-C14.
func TestMTC22ConfigByteBound(t *testing.T) {
	dir := t.TempDir()
	registry := testRegistry(t)

	// A document padded with comments to an exact size. Comments are the only
	// padding that cannot change the meaning of what is parsed.
	build := func(size int) []byte {
		body := "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: h.example.com\n"
		if len(body) >= size {
			return []byte(body[:size])
		}
		pad := make([]byte, size-len(body))
		for i := range pad {
			pad[i] = '#'
		}
		pad[len(pad)-1] = '\n'
		return append([]byte(body), pad...)
	}

	t.Run("exactly at the bound", func(t *testing.T) {
		path := filepath.Join(dir, "at-bound.yaml")
		if err := os.WriteFile(path, build(config.MaxBytes), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := config.LoadFile(path, registry); err != nil {
			t.Fatalf("a file exactly at the bound must be accepted: %v", err)
		}
	})

	t.Run("one byte over the bound", func(t *testing.T) {
		path := filepath.Join(dir, "over-bound.yaml")
		if err := os.WriteFile(path, build(config.MaxBytes+1), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := config.LoadFile(path, registry)
		assertCategory(t, err, config.CategorySource)
		if !strings.Contains(err.Error(), "larger than") {
			t.Errorf("err = %v, want an oversize refusal", err)
		}
	})

	t.Run("an empty file", func(t *testing.T) {
		path := filepath.Join(dir, "empty.yaml")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := config.LoadFile(path, registry)
		assertCategory(t, err, config.CategorySyntax)
	})

	t.Run("short malformed input", func(t *testing.T) {
		path := filepath.Join(dir, "short.yaml")
		if err := os.WriteFile(path, []byte("\tx"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := config.LoadFile(path, registry)
		assertCategory(t, err, config.CategorySyntax)
	})
}

// TestMTC21TheConfigFileMustBeARegularFile covers ADR 0071 section 8.1.
func TestMTC21TheConfigFileMustBeARegularFile(t *testing.T) {
	dir := t.TempDir()
	registry := testRegistry(t)

	t.Run("a directory", func(t *testing.T) {
		_, err := config.LoadFile(dir, registry)
		assertCategory(t, err, config.CategorySource)
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("err = %v, want a directory to be named as one", err)
		}
	})

	t.Run("a missing file", func(t *testing.T) {
		_, err := config.LoadFile(filepath.Join(dir, "absent.yaml"), registry)
		assertCategory(t, err, config.CategorySource)
		if !strings.Contains(err.Error(), "no such file") {
			t.Errorf("err = %v, want a missing-file refusal", err)
		}
	})

	t.Run("a symlink to a regular file is followed", func(t *testing.T) {
		real := filepath.Join(dir, "real.yaml")
		if err := os.WriteFile(real, []byte(validFourService), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(dir, "link.yaml")
		if err := os.Symlink(real, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := config.LoadFile(link, registry); err != nil {
			t.Errorf("a symlink to a regular file must be followed: %v", err)
		}
	})
}

// TestGenericFieldValidation covers the envelope's own rules.
func TestGenericFieldValidation(t *testing.T) {
	target := func(extra string) string {
		return "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: h.example.com\n" + extra
	}
	tests := []struct{ name, doc, want string }{
		{"missing host", "version: 1\ntargets:\n  - id: a\n    type: redis\n", "host is required"},
		{"host with a space", "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: \"a b\"\n", "space or a control character"},
		{"port zero", target("    port: 0\n"), "outside 1-65535"},
		{"port too high", target("    port: 70000\n"), "outside 1-65535"},
		{"negative port", target("    port: -1\n"), "outside 1-65535"},
		{"bare number timeout", target("    timeout: 30\n"), "must be written with a unit"},
		{"unparseable timeout", target("    timeout: \"soon\"\n"), "is not a duration"},
		{"negative timeout", target("    timeout: \"-5s\"\n"), "must be positive"},
		{"step above target timeout", target("    timeout: 5s\n    step_timeout: 10s\n"), "is above timeout"},
		{"bad tls mode", target("    tls:\n      mode: maybe\n"), "must be \"require\" or \"disable\""},
		{"ca_file under disable", target("    tls:\n      mode: disable\n      ca_file: /x.pem\n"), "no effect with"},
		{"server_name under disable", target("    tls:\n      mode: disable\n      server_name: x\n"), "no effect with"},
		{"insecure under disable", target("    tls:\n      mode: disable\n      insecure: true\n"), "no effect with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.doc)
			if err == nil {
				t.Fatalf("%s was accepted", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestRunSectionValidation covers ADR 0073's config-level run rules.
func TestRunSectionValidation(t *testing.T) {
	withRun := func(run string) string {
		return "version: 1\nrun:\n" + run +
			"targets:\n  - id: a\n    type: redis\n    host: h.example.com\n"
	}
	t.Run("concurrency zero is refused", func(t *testing.T) {
		_, err := load(t, withRun("  concurrency: 0\n"))
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "unlimited") {
			t.Errorf("err = %v, want the message to explain why zero is not a value", err)
		}
	})
	t.Run("negative concurrency is refused", func(t *testing.T) {
		_, err := load(t, withRun("  concurrency: -1\n"))
		assertCategory(t, err, config.CategoryInvalidField)
	})
	t.Run("concurrency above the maximum is refused", func(t *testing.T) {
		_, err := load(t, withRun(fmt.Sprintf("  concurrency: %d\n", config.MaxConcurrency+1)))
		assertCategory(t, err, config.CategoryInvalidField)
	})
	t.Run("concurrency at the maximum is accepted", func(t *testing.T) {
		cfg, err := load(t, withRun(fmt.Sprintf("  concurrency: %d\n", config.MaxConcurrency)))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Run.Concurrency != config.MaxConcurrency {
			t.Errorf("Concurrency = %d, want %d", cfg.Run.Concurrency, config.MaxConcurrency)
		}
	})
	t.Run("concurrency defaults when absent", func(t *testing.T) {
		cfg, err := load(t, "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: h.example.com\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Run.Concurrency != config.DefaultConcurrency {
			t.Errorf("Concurrency = %d, want the default %d",
				cfg.Run.Concurrency, config.DefaultConcurrency)
		}
	})
	t.Run("a run timeout below a target timeout is refused", func(t *testing.T) {
		_, err := load(t, "version: 1\nrun:\n  timeout: 10s\ntargets:\n"+
			"  - id: a\n    type: redis\n    host: h.example.com\n    timeout: 30s\n")
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "could never complete") {
			t.Errorf("err = %v, want the consequence stated", err)
		}
	})
	t.Run("no run timeout is valid", func(t *testing.T) {
		cfg, err := load(t, "version: 1\ntargets:\n  - id: a\n    type: redis\n    host: h.example.com\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Run.Timeout != 0 {
			t.Errorf("Run.Timeout = %s, want unset", cfg.Run.Timeout)
		}
	})
}

// TestRegistryBehaviour covers the extension point's own contract.
func TestRegistryBehaviour(t *testing.T) {
	t.Run("duplicate registration is refused", func(t *testing.T) {
		_, err := config.NewRegistry(redis.Factory{}, redis.Factory{})
		if err == nil {
			t.Fatal("registering one kind twice was accepted; it must not be last-wins")
		}
	})
	t.Run("a nil factory is refused", func(t *testing.T) {
		if _, err := config.NewRegistry(nil); err == nil {
			t.Fatal("a nil factory was accepted")
		}
	})
	t.Run("kinds are stable", func(t *testing.T) {
		registry := testRegistry(t)
		first := registry.Kinds()
		for range 8 {
			if !equalStrings(registry.Kinds(), first) {
				t.Fatalf("Kinds() is not stable: %v then %v", first, registry.Kinds())
			}
		}
	})
	t.Run("a registry with fewer services refuses the rest", func(t *testing.T) {
		registry, err := config.NewRegistry(redis.Factory{})
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		_, err = config.Load([]byte(validFourService), "c.yaml", registry)
		assertCategory(t, err, config.CategoryUnsupportedService)
	})
	t.Run("a nil registry is a programming error, not a config error", func(t *testing.T) {
		_, err := config.Load([]byte(validFourService), "c.yaml", nil)
		if err == nil {
			t.Fatal("a nil registry was accepted")
		}
	})
}

// TestErrorsCarryLocation proves a defect is findable in the file.
func TestErrorsCarryLocation(t *testing.T) {
	_, err := load(t, `
version: 1
targets:
  - id: first
    type: redis
    host: a.example.com
  - id: second
    type: redis
    host: b.example.com
    bogus: 1
`)
	if err == nil {
		t.Fatal("want a refusal")
	}
	var configErr *config.Error
	if !errors.As(err, &configErr) {
		t.Fatalf("err = %v, want a config.Error", err)
	}
	if configErr.Line() == 0 {
		t.Error("the error carries no line; a defect must be findable")
	}
	if !strings.Contains(err.Error(), "services.yaml") {
		t.Errorf("err = %v, want the source named", err)
	}
}

// TestTargetPathsAreQualified proves a nested defect names its target.
func TestTargetPathsAreQualified(t *testing.T) {
	_, err := load(t, `
version: 1
targets:
  - id: first
    type: redis
    host: a.example.com
  - id: second
    type: redis
    host: b.example.com
    port: 0
`)
	if err == nil {
		t.Fatal("want a refusal")
	}
	for _, want := range []string{"targets[1]", "second", "port"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
}

func TestCategoryNamesCoverEveryValue(t *testing.T) {
	// Every category must render as something other than the Go fallback, which
	// is what a missing entry in the names table would produce.
	for c := config.CategorySource; c <= config.CategoryCredentialReference; c++ {
		if !c.Valid() {
			t.Errorf("Category(%d) is not Valid", uint8(c))
		}
		if strings.HasPrefix(c.String(), "Category(") {
			t.Errorf("Category(%d) has no name", uint8(c))
		}
	}
	if config.CategoryUnspecified.Valid() {
		t.Error("CategoryUnspecified must not be Valid")
	}
}

func TestSourceKindNamesCoverEveryValue(t *testing.T) {
	for _, k := range []config.SourceKind{
		config.SourceNone, config.SourceEnv, config.SourceFile,
	} {
		if strings.HasPrefix(k.String(), "SourceKind(") {
			t.Errorf("SourceKind(%d) has no name", uint8(k))
		}
	}
}

// assertCategory fails unless err is a config.Error of the wanted category.
func assertCategory(t *testing.T, err error, want config.Category) {
	t.Helper()
	if err == nil {
		t.Fatalf("want a %s refusal, got no error", want)
	}
	if !errors.Is(err, config.ErrConfig) {
		t.Fatalf("err = %v, want it to match config.ErrConfig", err)
	}
	var configErr *config.Error
	if !errors.As(err, &configErr) {
		t.Fatalf("err = %v, want a *config.Error", err)
	}
	if got := configErr.Category(); got != want {
		t.Fatalf("category = %s, want %s (err: %v)", got, want, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
