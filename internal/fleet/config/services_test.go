package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services/redis"
)

// Per-service configuration validation.
//
// Every rule exercised here already exists as a leaf command's flag validation.
// These tests are what keep the two from drifting: a rule that is loosened on
// one side and not the other shows up as a case that changes here.

// TestServiceDefaultPortsMatchTheLeafCommands pins the four answers.
func TestServiceDefaultPortsMatchTheLeafCommands(t *testing.T) {
	tests := []struct {
		kind string
		want uint16
	}{
		{"postgres", 5432},
		{"kafka", 9092},
		{"redis", 6379},
		{"rabbitmq", 5672},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			doc := "version: 1\ntargets:\n  - id: t\n    type: " + tt.kind +
				"\n    host: h.example.com\n"
			switch tt.kind {
			case "postgres":
				doc += "    credentials:\n      username: u\n"
			case "kafka":
				doc += "    config:\n      sasl_mechanism: PLAIN\n"
			case "rabbitmq":
				doc += "    step_timeout: 10s\n"
			}
			cfg, err := load(t, doc)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Targets[0].Port; got != tt.want {
				t.Errorf("default port = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestPostgresRequiresAnIdentity is app.PostgresParams.validate's rule.
//
// The startup message has no anonymous form, so a role is required whether or
// not a password is configured — which is why this is PostgreSQL's rule and not
// the generic core's.
func TestPostgresRequiresAnIdentity(t *testing.T) {
	t.Run("no credentials block", func(t *testing.T) {
		_, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: postgres\n"+
			"    host: h.example.com\n")
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "startup message") {
			t.Errorf("err = %v, want the protocol reason stated", err)
		}
	})

	t.Run("an identity with no password is enough", func(t *testing.T) {
		cfg, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: postgres\n"+
			"    host: h.example.com\n    credentials:\n      username: svcdoctor\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.Targets[0].Credentials.Password.IsZero() {
			t.Error("want no credential reference")
		}
	})

	t.Run("database is optional", func(t *testing.T) {
		cfg, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: postgres\n"+
			"    host: h.example.com\n    credentials:\n      username: u\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := cfg.Targets[0].Config.(postgres.Config).Database; got != "" {
			t.Errorf("Database = %q, want empty", got)
		}
	})
}

// TestKafkaRequiresAMechanism is internal/cli/kafka.go's checkMechanism.
func TestKafkaRequiresAMechanism(t *testing.T) {
	base := "version: 1\ntargets:\n  - id: t\n    type: kafka\n    host: h.example.com\n"

	t.Run("absent", func(t *testing.T) {
		_, err := load(t, base)
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "never chooses one for you") {
			t.Errorf("err = %v, want the reason stated", err)
		}
	})

	t.Run("lowercase is refused with the uppercase spelling", func(t *testing.T) {
		_, err := load(t, base+"    config:\n      sasl_mechanism: plain\n")
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "PLAIN") {
			t.Errorf("err = %v, want the corrected spelling offered", err)
		}
	})

	t.Run("illegal characters are refused", func(t *testing.T) {
		_, err := load(t, base+"    config:\n      sasl_mechanism: \"PLAIN!\"\n")
		assertCategory(t, err, config.CategoryInvalidField)
	})

	t.Run("an over-long mechanism is refused", func(t *testing.T) {
		_, err := load(t, base+"    config:\n      sasl_mechanism: "+
			strings.Repeat("A", 21)+"\n")
		assertCategory(t, err, config.CategoryInvalidField)
	})

	t.Run("an unimplemented mechanism is accepted, because asking is the point", func(t *testing.T) {
		// GSSAPI is detect-and-explain only. Refusing the name here would remove
		// the only way to ask a broker what it wants (ADR 0057 §4).
		for _, mechanism := range []string{"GSSAPI", "AWS_MSK_IAM", "SCRAM-SHA-512", "OAUTHBEARER"} {
			if _, err := load(t, base+"    config:\n      sasl_mechanism: "+mechanism+"\n"); err != nil {
				t.Errorf("mechanism %q was refused: %v", mechanism, err)
			}
		}
	})
}

// TestKafkaIdentityPairing is internal/cli/kafka.go's checkKafkaIdentity.
func TestKafkaIdentityPairing(t *testing.T) {
	base := "version: 1\ntargets:\n  - id: t\n    type: kafka\n    host: h.example.com\n" +
		"    config:\n      sasl_mechanism: PLAIN\n"

	t.Run("a credential with no identity is refused", func(t *testing.T) {
		_, err := load(t, base+"    credentials:\n      password:\n        env: P\n")
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "no identity to authenticate as") {
			t.Errorf("err = %v, want the reason stated", err)
		}
	})

	t.Run("an identity with no credential is refused", func(t *testing.T) {
		_, err := load(t, base+"    credentials:\n      username: u\n")
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "only inside the SASL exchange") {
			t.Errorf("err = %v, want the reason stated", err)
		}
	})

	t.Run("neither is fine", func(t *testing.T) {
		if _, err := load(t, base); err != nil {
			t.Fatalf("a Kafka target with no credentials must be valid: %v", err)
		}
	})

	t.Run("both is fine", func(t *testing.T) {
		_, err := load(t, base+"    credentials:\n      username: u\n"+
			"      password:\n        env: P\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
}

// TestKafkaTakesNoBrokerList pins the absence documented in the package.
//
// app.KafkaParams has one bootstrap endpoint. Accepting a `brokers:` list would
// advertise a capability the composition root does not have.
func TestKafkaTakesNoBrokerList(t *testing.T) {
	for _, field := range []string{"brokers", "bootstrap_servers", "bootstrap"} {
		doc := "version: 1\ntargets:\n  - id: t\n    type: kafka\n    host: h.example.com\n" +
			"    config:\n      sasl_mechanism: PLAIN\n      " + field +
			":\n        - a.example.com:9092\n"
		if _, err := load(t, doc); err == nil {
			t.Errorf("%q was accepted; Kafka bootstraps from one endpoint", field)
		}
	}
}

// TestRedisAddsNoServiceField covers the deliberate emptiness.
func TestRedisAddsNoServiceField(t *testing.T) {
	base := "version: 1\ntargets:\n  - id: t\n    type: redis\n    host: h.example.com\n"

	t.Run("no config block is required", func(t *testing.T) {
		if _, err := load(t, base); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	t.Run("a db field is refused rather than ignored", func(t *testing.T) {
		// SELECT is not in the Redis BASIC allowlist, so `db:` would be
		// configuration for behaviour svcdoctor does not have. Accepting and
		// ignoring it is worse than refusing it.
		_, err := load(t, base+"    config:\n      db: 3\n")
		assertCategory(t, err, config.CategoryUnknownField)
	})

	t.Run("username is optional and never synthesized", func(t *testing.T) {
		cfg, err := load(t, base)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := cfg.Targets[0].Credentials.Username; got != "" {
			t.Errorf("Username = %q, want empty; `default` is never synthesized", got)
		}
	})
}

// TestRabbitMQVHost covers the default and the protocol maximum.
func TestRabbitMQVHost(t *testing.T) {
	base := "version: 1\ntargets:\n  - id: t\n    type: rabbitmq\n    host: h.example.com\n" +
		"    step_timeout: 10s\n"

	t.Run("the default is /", func(t *testing.T) {
		cfg, err := load(t, base)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := cfg.Targets[0].Config.(rabbitmq.Config).VHostOrDefault(); got != "/" {
			t.Errorf("VHostOrDefault() = %q, want %q", got, "/")
		}
	})

	t.Run("an explicit vhost is kept", func(t *testing.T) {
		cfg, err := load(t, base+"    config:\n      vhost: /production\n")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := cfg.Targets[0].Config.(rabbitmq.Config).VHostOrDefault(); got != "/production" {
			t.Errorf("VHostOrDefault() = %q", got)
		}
	})

	t.Run("an over-long vhost is refused rather than truncated", func(t *testing.T) {
		_, err := load(t, base+"    config:\n      vhost: \""+strings.Repeat("v", 128)+"\"\n")
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "protocol maximum") {
			t.Errorf("err = %v, want the protocol bound named", err)
		}
	})
}

// TestRabbitMQStepTimeoutFloor is ADR 0071 section 7.1's second clause, measured.
//
// The field is generic; the floor is RabbitMQ's alone. That is the whole reason
// the rule exists, so it is pinned on both sides: RabbitMQ refuses three seconds
// and the other three accept it.
func TestRabbitMQStepTimeoutFloor(t *testing.T) {
	rabbit := func(step string) string {
		return "version: 1\ntargets:\n  - id: t\n    type: rabbitmq\n" +
			"    host: h.example.com\n    step_timeout: " + step + "\n"
	}

	t.Run("at the floor is refused", func(t *testing.T) {
		_, err := load(t, rabbit("3s"))
		assertCategory(t, err, config.CategoryInvalidField)
		if !strings.Contains(err.Error(), "delays several refusals") {
			t.Errorf("err = %v, want the broker behaviour explained", err)
		}
	})

	t.Run("below the floor is refused", func(t *testing.T) {
		_, err := load(t, rabbit("1s"))
		assertCategory(t, err, config.CategoryInvalidField)
	})

	t.Run("above the floor is accepted", func(t *testing.T) {
		if _, err := load(t, rabbit("4s")); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	t.Run("the default satisfies the floor", func(t *testing.T) {
		cfg, err := load(t, "version: 1\ntargets:\n  - id: t\n    type: rabbitmq\n"+
			"    host: h.example.com\n")
		if err != nil {
			t.Fatalf("the default step timeout must satisfy RabbitMQ's floor: %v", err)
		}
		if got, want := cfg.Targets[0].StepTimeout, config.DefaultStepTimeout; got != want {
			t.Errorf("StepTimeout = %s, want %s", got, want)
		}
	})

	t.Run("the other three accept the same value RabbitMQ refuses", func(t *testing.T) {
		for _, kind := range []string{"postgres", "redis", "kafka"} {
			doc := "version: 1\ntargets:\n  - id: t\n    type: " + kind +
				"\n    host: h.example.com\n    step_timeout: 1s\n"
			switch kind {
			case "postgres":
				doc += "    credentials:\n      username: u\n"
			case "kafka":
				doc += "    config:\n      sasl_mechanism: PLAIN\n"
			}
			if _, err := load(t, doc); err != nil {
				t.Errorf("%s refused a 1s step timeout: %v; the floor is RabbitMQ's alone",
					kind, err)
			}
		}
	})
}

// TestDuplicateEndpointsAreDistinctTargets covers ADR 0073 section 9.
//
// The same server under two databases, two virtual hosts or two identities is
// the ordinary case, and it is why the endpoint is not identity.
func TestDuplicateEndpointsAreDistinctTargets(t *testing.T) {
	cfg, err := load(t, `
version: 1
targets:
  - id: orders
    type: postgres
    host: db.example.com
    port: 5432
    credentials:
      username: u
    config:
      database: orders
  - id: billing
    type: postgres
    host: db.example.com
    port: 5432
    credentials:
      username: u
    config:
      database: billing
`)
	if err != nil {
		t.Fatalf("two targets on one endpoint must be valid: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2; endpoints are never deduplicated", len(cfg.Targets))
	}
	if cfg.Targets[0].Host != cfg.Targets[1].Host || cfg.Targets[0].Port != cfg.Targets[1].Port {
		t.Fatal("the two targets should share an endpoint")
	}
	first := cfg.Targets[0].Config.(postgres.Config).Database
	second := cfg.Targets[1].Config.(postgres.Config).Database
	if first == second {
		t.Errorf("both targets resolved to database %q; each owns its own config", first)
	}
}

// TestValidationPerformsNoNetworkIO is the behavioural half of MT-C's
// no-network requirement.
//
// Every host below is unresolvable and every port is closed. If validation
// resolved or dialled anything, this would either fail or take a DNS timeout;
// it completes in microseconds because nothing here touches a network.
//
// The structural half — that the fleet packages import no network package at
// all — is in test/security/fleet_boundary_test.go, and it is the stronger of
// the two.
func TestValidationPerformsNoNetworkIO(t *testing.T) {
	doc := `
version: 1
targets:
  - id: unresolvable-postgres
    type: postgres
    host: this-name-does-not-exist.invalid
    credentials:
      username: u
  - id: unresolvable-kafka
    type: kafka
    host: also-does-not-exist.invalid
    config:
      sasl_mechanism: PLAIN
  - id: unresolvable-redis
    type: redis
    host: nor-this-one.invalid
  - id: unresolvable-rabbitmq
    type: rabbitmq
    host: certainly-not.invalid
    step_timeout: 10s
`
	start := time.Now()
	cfg, err := load(t, doc)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("validation must not require a host to resolve: %v", err)
	}
	if len(cfg.Targets) != 4 {
		t.Fatalf("len(Targets) = %d, want 4", len(cfg.Targets))
	}
	// A DNS lookup for a .invalid name takes milliseconds at best and seconds at
	// worst. This bound is loose enough never to flake and tight enough that four
	// resolutions could not hide inside it.
	if elapsed > time.Second {
		t.Errorf("validation took %s; it must perform no network I/O", elapsed)
	}
}

// TestEveryFactoryReportsItsOwnKind keeps the registry key and the value in step.
func TestEveryFactoryReportsItsOwnKind(t *testing.T) {
	tests := []struct {
		factory config.Factory
		config  config.ServiceConfig
	}{
		{postgres.Factory{}, postgres.Config{}},
		{kafka.Factory{}, kafka.Config{}},
		{redis.Factory{}, redis.Config{}},
		{rabbitmq.Factory{}, rabbitmq.Config{}},
	}
	for _, tt := range tests {
		if got, want := tt.config.Kind(), tt.factory.Kind(); got != want {
			t.Errorf("config kind %q does not match factory kind %q", got, want)
		}
		if tt.factory.DefaultPort() == 0 {
			t.Errorf("%s registered a zero default port", tt.factory.Kind())
		}
	}
}
