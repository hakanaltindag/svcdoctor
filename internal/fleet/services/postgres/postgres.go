// Package postgres owns the PostgreSQL shape of a multi-target configuration.
//
// It decodes and validates. It executes nothing, opens no socket, resolves no
// name and reads no credential: Phase 9.1A builds the configuration foundation
// and Phase 9.1B gives this package the call into app.DiagnosePostgres.
//
// # Every rule here already existed
//
// The fields are `diagnose postgres`'s flags, the requiredness is
// app.PostgresParams.validate's, and nothing is more permissive than the leaf
// command. That is the whole point of ADR 0071 section 6.3: a service's
// configuration is that service's existing input surface expressed in a file,
// not a second contract that can drift from the first.
package postgres

import (
	"context"
	"fmt"

	adapterpostgres "github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/trustsource"
)

// Kind is the value of a target's `type` field.
const Kind = "postgres"

// DefaultPort is PostgreSQL's registered port, and `diagnose postgres`'s default.
//
// A default port is service-owned rather than generic because 5432, 9092, 6379
// and 5672 are four different answers. This is not the inference ADR 0011
// refuses — that one goes from a port to a service, and this goes the other way,
// after the operator has already said which service it is.
const DefaultPort = 5432

// Config is a PostgreSQL target's own configuration.
//
// One field, because PostgreSQL adds exactly one thing to the generic envelope.
// `user` is not here: it is the credential identity, which every service maps
// through the same generic `credentials.username` (ADR 0071 §7.2).
type Config struct {
	// Database is the database to select in the startup message. Empty means
	// PostgreSQL's own default, which is the role name — the same behaviour as
	// `diagnose postgres` with no `--database`.
	Database string `yaml:"database"`
}

// Kind reports the service this configuration belongs to.
func (c Config) Kind() string { return Kind }

// Factory registers PostgreSQL with the generic configuration core and with the
// runner registry.
//
// One type implementing both interfaces, so a service is registered once. The
// zero Factory is usable for configuration alone — Decode reads no field — which
// is what lets configuration be validated on a machine with no network.
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
//
// # The identity requirement is PostgreSQL's, and it is not about credentials
//
// app.PostgresParams.validate refuses an empty Role, and it refuses it whether
// or not a password is configured. The reason is protocol: the startup message
// has no anonymous form, so a PostgreSQL run must name a role before it can ask
// anything at all. That is why this is checked here and not in the generic core
// — the other three services accept a target with no identity.
func (Factory) Decode(node *config.ServiceNode, common config.Common) (config.ServiceConfig, error) {
	var cfg Config
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}

	if common.Credentials.Username == "" {
		return nil, config.InvalidField("credentials.username",
			"a PostgreSQL target requires credentials.username: it is the role named in the "+
				"startup message, which has no anonymous form, so it is required whether or "+
				"not a password is configured")
	}

	return cfg, nil
}

// Factory is also this service's runner. Run turns a validated target into
// app.PostgresParams and calls the existing composition root.
//
// # It calls DiagnosePostgres and reaches nothing past it
//
// No adapter, no wire package, no probe beyond the injected seams, no diagnosis
// rule. Credential authority, connection ownership, the one-path-past-the-
// credential-boundary rule and every claim discipline stay exactly where they
// already are — this is a parameter mapping, and it is deliberately boring.
//
// The credential arrives already bound to this target's own endpoint.
// PostgresParams.validate checks that binding a second time and refuses a
// credential bound anywhere else, so the fleet layer cannot rebind one even by
// mistake.
func (f Factory) Run(
	ctx context.Context, target config.Target, credential security.Credential,
) (run.Outcome, error) {
	cfg, ok := target.Config.(Config)
	if !ok {
		return run.Outcome{}, fmt.Errorf(
			"postgres runner received %T, which is not a PostgreSQL configuration", target.Config)
	}

	roots, err := trustsource.Load(target.TLS.CAFile)
	if err != nil {
		return run.Outcome{}, fmt.Errorf("loading the trust source: %w", err)
	}

	plan := adapterpostgres.TLSRequired
	if !target.TLS.Enabled() {
		plan = adapterpostgres.TLSDisabled
	}

	result, err := app.DiagnosePostgres(ctx, app.PostgresParams{
		Host:     target.Host,
		Port:     target.Port,
		Role:     target.Credentials.Username,
		Database: cfg.Database,

		Credential: credential,

		Resolver: f.Env.Resolver,
		Dialer:   f.Env.Dialer,

		TLS: plan,
		TLSOptions: adapterpostgres.TLSOptions{
			ServerName:         target.TLS.ServerName,
			RootCAs:            roots,
			InsecureSkipVerify: target.TLS.Insecure,
		},

		StepTimeout: target.StepTimeout,
		Vantage:     f.Env.Vantage,
		Version:     f.Env.Version,
	})
	if err != nil {
		return run.Outcome{}, err
	}
	return run.Outcome{Report: result.Report(), Incomplete: result.Incomplete()}, nil
}
