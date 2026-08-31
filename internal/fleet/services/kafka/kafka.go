// Package kafka owns the Kafka shape of a multi-target configuration.
//
// It decodes and validates. It executes nothing, opens no socket, resolves no
// name and reads no credential.
//
// # There is one bootstrap endpoint, not a broker list
//
// A configuration names `host` and `port`, the same single bootstrap endpoint
// `diagnose kafka` takes. There is deliberately no `brokers:` list, because
// app.KafkaParams has no such input: a run bootstraps from one endpoint and the
// cluster's own Metadata response supplies the rest, which are then swept
// credential-free (ADR 0050). Accepting a list here would advertise a capability
// the composition root does not have, and svcdoctor would have to either ignore
// the extra entries or invent behaviour nobody decided.
package kafka

import (
	"context"
	"fmt"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Kind is the value of a target's `type` field.
const Kind = "kafka"

// DefaultPort is `diagnose kafka`'s default port.
const DefaultPort = 9092

// maxMechanismBytes bounds a SASL mechanism name.
//
// Twenty, which is internal/cli/kafka.go's existing bound, inherited rather than
// re-derived so that a mechanism accepted by the flag is accepted here.
const maxMechanismBytes = 20

// Config is a Kafka target's own configuration.
type Config struct {
	// SASLMechanism is the mechanism to propose to the bootstrap broker.
	//
	// Required, and required for a protocol reason rather than a stylistic one:
	// the Kafka protocol has no "list your mechanisms" request, so a client
	// proposes one and the broker's answer carries the list. svcdoctor never
	// chooses one, because choosing would make the report describe a mechanism
	// the operator did not ask about (ADR 0026, ADR 0057).
	SASLMechanism string `yaml:"sasl_mechanism"`
}

// Kind reports the service this configuration belongs to.
func (c Config) Kind() string { return Kind }

// Factory registers Kafka with the generic configuration core and with the
// runner registry.
//
// One type implementing both interfaces, so a service is registered once. The
// zero Factory is usable for configuration alone — Decode reads no field.
type Factory struct {
	// Env carries the probe seams, the vantage and the version. Required for
	// Run; unused by Decode.
	Env services.Environment
}

// Kind returns the registration key.
func (Factory) Kind() string { return Kind }

// DefaultPort returns the port used when a target names none.
func (Factory) DefaultPort() uint16 { return DefaultPort }

// Decode turns the `config:` subtree into a Config and validates the target.
func (Factory) Decode(node *config.ServiceNode, common config.Common) (config.ServiceConfig, error) {
	var cfg Config
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}

	if err := checkMechanism(cfg.SASLMechanism); err != nil {
		return nil, err
	}
	if err := checkIdentity(common.Credentials); err != nil {
		return nil, err
	}

	return cfg, nil
}

// checkMechanism enforces internal/cli/kafka.go's grammar, unchanged.
//
// A mechanism name is a protocol parameter drawn from a public registry, like a
// TLS server name: naming one sends nothing secret and costs the broker no
// authentication attempt. So the grammar is checked and the *set* is not — an
// unimplementable mechanism is answered with UNKNOWN and an INFO finding, which
// is the only way to ask a broker what it wants (ADR 0057 §4).
func checkMechanism(mechanism string) error {
	if mechanism == "" {
		return config.InvalidField("config.sasl_mechanism",
			"a Kafka target requires config.sasl_mechanism; svcdoctor never chooses one for "+
				"you, because the protocol has no request that lists a broker's mechanisms — "+
				"a client proposes one and the answer carries the list")
	}
	if len(mechanism) > maxMechanismBytes {
		return config.InvalidField("config.sasl_mechanism", fmt.Sprintf(
			"SASL mechanism %q is longer than %d characters", mechanism, maxMechanismBytes))
	}
	for i := 0; i < len(mechanism); i++ {
		c := mechanism[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		case c >= 'a' && c <= 'z':
			return config.InvalidField("config.sasl_mechanism", fmt.Sprintf(
				"SASL mechanism %q must be uppercase; mechanism names are registered in "+
					"uppercase, so write %q", mechanism, strings.ToUpper(mechanism)))
		default:
			return config.InvalidField("config.sasl_mechanism", fmt.Sprintf(
				"SASL mechanism %q may contain only A-Z, 0-9, hyphen and underscore",
				mechanism))
		}
	}
	return nil
}

// checkIdentity refuses the two combinations that would mislead.
//
// internal/cli/kafka.go's checkKafkaIdentity, expressed against a configuration
// rather than against flags. Both halves matter: a credential with no identity
// has nothing to authenticate as, and an identity with no credential is inert,
// because a Kafka run sends an identity only inside the SASL exchange.
func checkIdentity(credentials config.Credentials) error {
	configured := !credentials.Password.IsZero()
	switch {
	case configured && credentials.Username == "":
		return config.InvalidField("credentials.username",
			"credentials.username is required alongside credentials.password; the credential "+
				"has no identity to authenticate as")
	case !configured && credentials.Username != "":
		return config.InvalidField("credentials.username",
			"credentials.username has no effect without credentials.password; a Kafka run "+
				"sends an identity only inside the SASL exchange")
	}
	return nil
}

// Run turns a validated target into app.KafkaParams and calls the existing
// composition root.
//
// The bootstrap endpoint is the credential authority boundary and a Metadata
// response cannot widen it: an advertised broker receives credential-free DNS,
// TCP and TLS and nothing else (ADR 0050). Nothing here changes that — the
// composition root owns it, and this is a parameter mapping.
func (f Factory) Run(
	ctx context.Context, target config.Target, credential security.Credential,
) (run.Outcome, error) {
	cfg, ok := target.Config.(Config)
	if !ok {
		return run.Outcome{}, fmt.Errorf(
			"kafka runner received %T, which is not a Kafka configuration", target.Config)
	}

	options, err := services.TLSOptions(target.TLS)
	if err != nil {
		return run.Outcome{}, err
	}

	result, err := app.DiagnoseKafka(ctx, app.KafkaParams{
		Host:        target.Host,
		Port:        target.Port,
		Mechanism:   cfg.SASLMechanism,
		Credential:  credential,
		Resolver:    f.Env.Resolver,
		Dialer:      f.Env.Dialer,
		TLS:         options,
		StepTimeout: target.StepTimeout,
		Vantage:     f.Env.Vantage,
		Version:     f.Env.Version,
	})
	if err != nil {
		return run.Outcome{}, err
	}
	return run.Outcome{Report: result.Report(), Incomplete: result.Incomplete()}, nil
}
