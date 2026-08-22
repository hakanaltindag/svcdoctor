package cli

import (
	"fmt"
	"io"
)

// The usage text is written by hand rather than produced by flag.FlagSet.
//
// Two reasons, and both are about the contract rather than about taste. It has
// to be byte-deterministic, because these tests are golden and a Go release that
// reflowed flag's default output would fail them for no product reason. And the
// destination differs by *why* it is being printed — requested help is an
// artifact and goes to stdout, help shown because an invocation was wrong is a
// diagnostic and goes to stderr — which a FlagSet's single Output cannot express.
//
// Nothing here documents a flag that does not exist. Phase 5.2 added
// --password-file, --password-stdin and --shareable, so those appear; a literal
// --password, an environment variable and an interactive prompt do not, because
// ADR 0049 refuses the first and defers the other two. Neither do --color,
// --verbose, inspect or kafka.
//
// The credential wording says what each flag reads and stops there. Calling a
// source "safe" or "secure" would be an absolute claim about the operator's
// filesystem and pipeline, which this tool is in no position to make.

func (a *App) usageRoot(w io.Writer) {
	_, _ = fmt.Fprint(w, `svcdoctor diagnoses service connectivity from where you run it.

Usage:
  svcdoctor <command> [arguments]

Commands:
  diagnose    measure a service and report what was observed

Flags:
  --help      show this help
  --version   show the svcdoctor version

Run "svcdoctor diagnose --help" for the services that can be diagnosed.
`)
}

func (a *App) usageDiagnose(w io.Writer) {
	_, _ = fmt.Fprint(w, `Measure a service and report what was observed.

Usage:
  svcdoctor diagnose <service> [flags]

Services:
  postgres    diagnose a PostgreSQL endpoint

Run "svcdoctor diagnose postgres --help" for its flags.
`)
}

func (a *App) usagePostgres(w io.Writer) {
	_, _ = fmt.Fprint(w, `Diagnose a PostgreSQL endpoint.

svcdoctor behaves as the PostgreSQL client you describe and reports what it
observed at every stage: name resolution, the connection, the in-band SSL
negotiation, the TLS handshake, the startup exchange, authentication and session
establishment.

Usage:
  svcdoctor diagnose postgres --host <host> --user <role> [flags]

Required:
  --host string             the endpoint to diagnose
  --user string             the role to connect as

Connection:
  --port uint               the port to connect to (default 5432)
  --database string         the database to select; empty lets the server
                            default it to the role name

Execution budget:
  --timeout duration        bound on the whole run (default 30s)
  --step-timeout duration   bound on each individual exchange (default 10s)

Transport encryption:
  --tls string              "require" or "disable" (default "require")
  --tls-ca-file path        PEM trust source; empty uses the system store
  --tls-server-name string  identity to verify and send in SNI; empty uses
                            the host
  --tls-insecure            do not verify the endpoint's identity. Explicit,
                            never automatic, and recorded in the report. The
                            resulting channel is unverified, which the
                            credential transport policy refuses, so a
                            credential would be withheld rather than sent

Credential:
  --password-file path      read the PostgreSQL credential from a file
  --password-stdin          read the PostgreSQL credential from stdin

  At most one may be given. Supplying neither is a valid run: an endpoint that
  demands authentication is reported as such, and nothing is sent.

Output:
  --output string           "json" (default "json")
  --shareable               produce the shareable redacted report instead of
                            the local one, using the same diagnosis

Exit codes:
  0   a report was produced and no error-level problem was proven
  1   a report was produced and an error-level problem was proven
  2   svcdoctor was invoked with something it cannot act on
  3   svcdoctor failed and produced no usable report
  4   a report was produced but svcdoctor's own execution did not finish

Exit code 0 does not mean a session was established. Read the report.
`)
}
