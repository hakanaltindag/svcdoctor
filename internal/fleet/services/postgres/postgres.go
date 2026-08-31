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
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
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

// Factory registers PostgreSQL with the generic configuration core.
type Factory struct{}

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
