package cli

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// maxCredentialInput bounds the credential material this command will read.
//
// ADR 0049 section 3 fixes it at 4 KiB: far above any password a SCRAM exchange
// can carry — svcdoctor already restricts passwords to printable ASCII — and far
// below a size that indicates the operator pointed at the wrong file. Something
// larger is much more likely to be a certificate, a key or a config.
//
// # The bound is on the input, not on the resulting secret
//
// ADR 0049 bounds what is *read*: "Read the file whole, subject to a bounded
// maximum", and "Reject **input** above the bound". So a 4096-byte password
// followed by a newline is 4097 bytes of input and is refused, even though the
// secret it would yield is exactly at the bound. That is the reading both of the
// ADR's sentences support, and the alternative — bounding the trimmed secret —
// appears nowhere in it.
//
// The distinction only becomes visible within one byte of a limit no real
// password approaches, and refusing is the safe direction: a rejected
// invocation is fixable, a truncated secret authenticates as a wrong one.
const maxCredentialInput = 4096

// credentialSources names what the invocation selected.
type credentialSources struct {
	file      string
	fromStdin bool
}

// validate enforces exclusivity.
//
// # No precedence, deliberately
//
// Two sources is an error rather than a resolution. A precedence rule is one
// more thing to remember under pressure, and the failure it hides — *svcdoctor
// used the other credential* — is exactly the one that costs an hour during an
// incident. Refusing ambiguity is stronger than resolving it (ADR 0049 §2).
func (c credentialSources) validate() error {
	if c.file != "" && c.fromStdin {
		return usagef("--password-file and --password-stdin are mutually exclusive")
	}
	return nil
}

// readSecret returns the credential material the invocation selected.
//
// # No source is not an error
//
// It returns the zero Secret, and that is a valid run. An endpoint demanding
// authentication then produces POSTGRES_CREDENTIAL_NOT_CONFIGURED — a truthful
// WARN at exit 0 — which is why this command never has to acquire a credential
// it was not given, and why there is no prompt (ADR 0049 §2).
//
// # There is no fallback between sources
//
// A named source that cannot be read is an error. It is never quietly replaced
// by the other one: an operator who wrote --password-file must not silently
// authenticate with whatever happened to be on stdin.
func (a *App) readSecret(sources credentialSources) (security.Secret, error) {
	switch {
	case sources.file != "":
		return a.readSecretFile(sources.file)
	case sources.fromStdin:
		plaintext, err := readBoundedSecret(a.In)
		if err != nil {
			return security.Secret{}, usagef("reading the credential from stdin: %s", err)
		}
		return security.NewSecret(plaintext), nil
	default:
		return security.Secret{}, nil
	}
}

// readSecretFile reads credential material from a path the operator named.
//
// The **path** appears in errors, because a file svcdoctor cannot use has to be
// nameable or the operator cannot fix it. The **contents** appear nowhere, and
// neither does their length: a size is a fact derived from the secret and it
// buys the reader nothing (ADR 0049 §3).
func (a *App) readSecretFile(path string) (security.Secret, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the path is the operator's own flag.
	if err != nil {
		return security.Secret{}, usagef(
			"--password-file %s cannot be read: %s", path, openReason(err))
	}
	// Closed on every path, including the oversize refusal below.
	defer func() { _ = file.Close() }()

	// A directory opens successfully and fails on read with a platform-specific
	// error, so it is named here rather than left to surface as "unreadable".
	info, err := file.Stat()
	if err != nil {
		return security.Secret{}, usagef("--password-file %s cannot be read: unreadable", path)
	}
	if info.IsDir() {
		return security.Secret{}, usagef("--password-file %s is a directory", path)
	}

	plaintext, err := readBoundedSecret(file)
	if err != nil {
		return security.Secret{}, usagef("--password-file %s: %s", path, err)
	}
	return security.NewSecret(plaintext), nil
}

// errCredentialTooLarge is the oversize refusal, phrased without the size.
var errCredentialTooLarge = errors.New("credential input exceeds the 4 KiB limit")

// readBoundedSecret reads at most one byte past the limit and refuses the rest.
//
// # Why one byte past
//
// It is the smallest read that can tell "exactly at the bound" from "over it".
// Reading exactly the limit cannot distinguish a 4096-byte secret from the first
// 4096 bytes of a certificate, and truncating either would hand the endpoint a
// credential the operator never chose.
//
// # Exactly one trailing line ending, and nothing else
//
// strings.TrimSpace is forbidden here. A leading or trailing space is legal
// PostgreSQL password material, and removing it silently would turn a correct
// credential into POSTGRES_CREDENTIALS_REJECTED — the single most misleading
// outcome this tool can produce, because it accuses the operator's secret store
// of being wrong. One trailing newline goes because every editor and `echo` adds
// one; a second one is the operator's data (ADR 0049 §3).
func readBoundedSecret(r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("no input to read from")
	}

	raw, err := io.ReadAll(io.LimitReader(r, maxCredentialInput+1))
	if err != nil {
		// The error comes from the reader and describes the read, never the
		// bytes: io.ReadAll does not put what it read into what it returns.
		return "", errors.New("unreadable")
	}
	if len(raw) > maxCredentialInput {
		return "", errCredentialTooLarge
	}

	return trimOneLineEnding(string(raw)), nil
}

// trimOneLineEnding removes a single trailing "\r\n" or "\n", and nothing else.
func trimOneLineEnding(s string) string {
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2]
	case strings.HasSuffix(s, "\n"):
		return s[:len(s)-1]
	default:
		return s
	}
}

// credentialFor binds a secret to the endpoint that authorizes it.
//
// # An empty secret produces no credential at all, and that is load-bearing
//
// security.NewSecret("") is the zero Secret, but security.Credential.IsZero
// reads only its **endpoint** — so a credential built around an empty secret is
// *not* zero, and internal/adapter/postgres would walk straight past its
// "nothing to present" branch and attempt SCRAM with an empty password.
//
// So an empty source leaves the credential unset, which is the honest mapping:
// the run was given nothing to present, which is exactly what
// EXEC_REQUIRED_INPUT_MISSING means. An empty file, a file holding one newline,
// and no --password-file at all therefore reach the same place, and none of them
// puts a byte on the wire.
func credentialFor(host string, port uint16, role string, secret security.Secret) (
	security.Credential, error,
) {
	if secret.IsEmpty() {
		return security.Credential{}, nil
	}

	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		return security.Credential{}, usagef("binding the credential to %s: %v", host, err)
	}
	credential, err := security.NewCredential(endpoint, role, secret)
	if err != nil {
		return security.Credential{}, usagef("building the credential: %v", err)
	}
	return credential, nil
}

// openReason reduces a filesystem error to its cause, naming nothing else.
func openReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "no such file"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "unreadable"
	}
}
