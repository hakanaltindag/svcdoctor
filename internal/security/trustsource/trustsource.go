// Package trustsource loads PEM trust material from a path an operator named.
//
// It is the single implementation of ADR 0058 section 2's rule, extracted in
// Phase 9.1B so that the fleet service runners and the four leaf commands load
// trust material the same way.
//
// # Why one implementation rather than two
//
// ADR 0060 exists because the TLS-flag contract was previously in two places and
// the two disagreed — Kafka refused three flags under `--tls disable` and
// PostgreSQL accepted and ignored them, one of those was right, and nothing in
// the build noticed. A second PEM loader in the fleet layer would be the same
// defect in a different field: two answers to "is this file acceptable trust
// material", drifting silently.
package trustsource

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// MaxBytes bounds the trust material a run will read.
//
// A PEM bundle of system-CA size is well under this; anything larger is much
// more likely to be the wrong file than a trust store, and failing loudly beats
// reading an arbitrary amount of a file an operator pointed at by mistake.
const MaxBytes = 1 << 20

// ErrTooLarge reports that the file is above MaxBytes.
var ErrTooLarge = fmt.Errorf("trust source is larger than %d bytes", MaxBytes)

// ErrNoCertificate reports that the file held no PEM certificate.
var ErrNoCertificate = errors.New("trust source contains no PEM certificate")

// Load returns the trust pool for path, or nil for the system trust store.
//
// # It replaces the system roots; it never extends them
//
// The pool starts empty and holds exactly what the supplied file contained. That
// is ADR 0058 section 2, and it is the clause that lets a trust source express
// *only this issuer is acceptable here* — a run configured with the wrong CA
// fails rather than quietly succeeding through a public root.
//
// # The path may appear in a caller's error; the contents never do
//
// A file svcdoctor cannot use has to be nameable or the operator cannot fix it.
// Its bytes are a different matter: a trust file holds no secret, but the rule
// that file contents never reach an error message is worth keeping uniform with
// ADR 0049 rather than reasoned about per file. This function names neither —
// each caller phrases its own refusal around the sentinels above.
func Load(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxBytes {
		return nil, ErrTooLarge
	}

	pem, err := os.ReadFile(path) //nolint:gosec // G304: the operator's own path, bounded above.
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, ErrNoCertificate
	}
	return pool, nil
}

// Reason phrases why Load refused, without naming the path.
//
// # Why the phrasing moved here in Phase 9.2B
//
// It was in internal/cli, where the four leaf commands used it. The fleet
// preflight added in Phase 9.2B needs the same three answers for the same three
// sentinels, and copying eight lines would have been a second opinion about what
// "unusable trust material" means — the exact defect this package's own doc
// comment says it exists to prevent.
//
// The caller supplies the subject, so each surface names what the operator can
// act on:
//
//	--tls-ca-file /etc/ca.pem cannot be read: no such file      (leaf command)
//	target "orders-db": tls.ca_file: cannot be read: no such file  (fleet)
//
// The path is the caller's to include or omit; this function never echoes it,
// and it never carries anything the file held.
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTooLarge):
		return fmt.Sprintf("is larger than %d bytes", MaxBytes)
	case errors.Is(err, ErrNoCertificate):
		return "contains no PEM certificate"
	case errors.Is(err, os.ErrNotExist):
		return "cannot be read: no such file"
	case errors.Is(err, os.ErrPermission):
		return "cannot be read: permission denied"
	default:
		return "cannot be read: unreadable"
	}
}
