package cli

import (
	"crypto/x509"
	"errors"
	"os"

	"github.com/hakanaltindag/svcdoctor/internal/security/trustsource"
)

// This file is the whole of the TLS-flag contract, for every service.
//
// It exists because the contract was previously in two places and the two
// disagreed: Kafka refused `--tls-ca-file`, `--tls-server-name` and
// `--tls-insecure` under `--tls disable`, and PostgreSQL accepted all three and
// ignored them. One of those was right, both were reachable, and nothing in the
// build noticed. ADR 0060 decides which, and this file is the single place a
// third service inherits the answer from rather than re-deriving it.

// maxCAFileSize bounds the trust material a command will read.
//
// The value and its justification live in internal/security/trustsource, which
// Phase 9.1B extracted so that a fleet run and a leaf command load trust
// material through one implementation rather than two.
const maxCAFileSize = trustsource.MaxBytes

// tlsFlags is the TLS surface every service's flag set exposes.
//
// The four are identical across services on purpose, and grouping them makes
// that a fact of the type rather than a coincidence of two flag sets. A service
// that needed a fifth would extend this and inherit the refusals below.
type tlsFlags struct {
	// mode is the `--tls` value verbatim, validated by the service's own plan
	// builder. This file does not interpret it beyond "disabled or not",
	// because what `require` *means* differs between an in-band negotiation and
	// an ordinary handshake.
	disabled bool

	caFile     string
	serverName string
	insecure   bool
}

// refuseInertTLSFlags rejects TLS-only flags on a run that performs no
// handshake.
//
// # Why refusal rather than silent acceptance
//
// `--tls disable --tls-ca-file ca.pem` describes a run with no handshake to
// apply the trust source to, and `--tls disable --tls-insecure` describes a run
// with no verification to disable. Accepting either lets an operator believe
// they configured — or deliberately relaxed — the security of a connection that
// was never going to be encrypted at all. The second is the worse of the two:
// an operator who passed `--tls-insecure` believes they are running an
// unverified TLS connection, and they are running no TLS connection.
//
// Inert configuration is not free. A flag that is accepted and ignored is
// indistinguishable, at the call site, from a flag that is accepted and honoured
// — so the invocation an operator copies into a runbook keeps whatever meaning
// they first read into it, and nothing ever corrects them.
//
// # It is input validation, not a diagnosis
//
// The refusal happens before the composition root is called, so nothing is
// dialled, nothing is resolved and no report exists. Exit 2, the flag named, the
// reason stated. See ADR 0060 section 4 for why the alternative — accepting
// them as documented no-ops — was declined.
//
// # One flag per message, in a fixed order
//
// An operator who passed all three gets told about `--tls-ca-file` first, fixes
// it, and is told about the next. Listing all three at once reads as though they
// interact, and they do not: each is independently inert.
func refuseInertTLSFlags(f tlsFlags) error {
	if !f.disabled {
		return nil
	}
	switch {
	case f.caFile != "":
		return usagef("--tls-ca-file has no effect with --tls disable")
	case f.serverName != "":
		return usagef("--tls-server-name has no effect with --tls disable")
	case f.insecure:
		return usagef("--tls-insecure has no effect with --tls disable")
	}
	return nil
}

// trustSource loads the PEM trust material, or reports that it could not.
//
// The rules are internal/security/trustsource's; the wording is this package's,
// because an operator has to be told which flag to fix. A nil pool means the
// system trust store, which is what the adapter documents and what an operator
// who passed no flag asked for.
func trustSource(path string) (*x509.CertPool, error) {
	pool, err := trustsource.Load(path)
	switch {
	case err == nil:
		return pool, nil
	case errors.Is(err, trustsource.ErrTooLarge):
		return nil, usagef("--tls-ca-file %s is larger than %d bytes", path, maxCAFileSize)
	case errors.Is(err, trustsource.ErrNoCertificate):
		return nil, usagef("--tls-ca-file %s contains no PEM certificate", path)
	default:
		return nil, usagef("--tls-ca-file %s cannot be read: %v", path, statReason(err))
	}
}

// statReason reduces a filesystem error to its cause without echoing the path a
// second time or carrying anything the file held.
func statReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "no such file"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "unreadable"
	}
}
