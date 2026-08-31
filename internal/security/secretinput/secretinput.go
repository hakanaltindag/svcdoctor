// Package secretinput reads credential material from a bounded source.
//
// It is the single implementation of the semantics ADR 0049 section 3 fixed for
// `--password-file` and `--password-stdin`, extracted in Phase 9.1A so that a
// second caller could exist without a second interpretation. ADR 0072 section 12
// requires exactly that: a fleet configuration's `file:` reference uses the
// semantics the flag already has, and *"nothing in this record creates a second
// interpretation of a secret file"*.
//
// Before this package the rules lived in internal/cli. A copy in the fleet
// resolver would have been two implementations of one contract, drifting
// silently — which is the failure ADR 0060 found when the TLS-flag contract was
// in two places and the two disagreed.
//
// # What it does not do
//
// It builds no security.Secret and no security.Credential. It returns a plain
// string, because the caller decides what the material becomes: internal/cli
// binds it to the endpoint its flags named, and internal/fleet/secret binds it
// to the target's own endpoint. A package that produced a bound credential would
// have to know which endpoint authorizes it, and neither caller's endpoint is
// knowable from a path.
//
// It also formats no operator-facing message. Every error here is a sentinel or
// a wrapped filesystem error, and each caller phrases its own refusal — one
// naming a flag, the other naming a target and a field. The mechanism is shared;
// the wording is not, because the two arrive from different places and an
// operator has to be told which one to fix.
package secretinput

import (
	"errors"
	"io"
	"os"
	"strings"
)

// MaxInput bounds the credential material any source may supply.
//
// ADR 0049 section 3 fixes it at 4 KiB: far above any password a SCRAM exchange
// can carry — svcdoctor already restricts PostgreSQL passwords to printable
// ASCII — and far below a size that indicates the operator pointed at the wrong
// file. Something larger is much more likely to be a certificate, a key or a
// configuration.
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
// password approaches, and refusing is the safe direction: a rejected invocation
// is fixable, a truncated secret authenticates as a wrong one.
const MaxInput = 4096

// ErrTooLarge is the oversize refusal, phrased without the size of what was read.
//
// The "4 KiB" text is load-bearing: it is the operator's only clue about which
// limit they crossed, and tests in both callers assert it. It carries no fact
// derived from the material itself.
var ErrTooLarge = errors.New("credential input exceeds the 4 KiB limit")

// ErrIsDirectory reports that the path named a directory.
//
// It is separate from ErrUnreadable because a directory opens successfully and
// fails on read with a platform-specific error, so without this it would surface
// as "unreadable" — true, unhelpful, and one of the easiest mistakes to make
// when a secret is mounted as a volume rather than as a file.
var ErrIsDirectory = errors.New("path is a directory")

// ErrUnreadable reports that a source could not be read.
//
// The error from the reader describes the read and never the bytes: io.ReadAll
// does not put what it read into what it returns, and this constant makes sure
// nothing else does either.
var ErrUnreadable = errors.New("unreadable")

// ErrNoReader reports that there was no source to read from.
var ErrNoReader = errors.New("no input to read from")

// Read returns the credential material r supplies, bounded and trimmed.
//
// # Why one byte past the limit is read
//
// It is the smallest read that can tell "exactly at the bound" from "over it".
// Reading exactly the limit cannot distinguish a 4096-byte secret from the first
// 4096 bytes of a certificate, and truncating either would hand an endpoint a
// credential the operator never chose.
func Read(r io.Reader) (string, error) {
	if r == nil {
		return "", ErrNoReader
	}

	raw, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return "", ErrUnreadable
	}
	if len(raw) > MaxInput {
		return "", ErrTooLarge
	}

	return TrimOneLineEnding(string(raw)), nil
}

// ReadFile returns the credential material stored at path.
//
// It follows symlinks, because os.Open does and because a secret delivered by a
// container runtime or a Kubernetes projected volume is reached through one.
//
// It deliberately does **not** require a regular file. That is not an oversight:
// `--password-stdin` already accepts a pipe, the four leaf commands have always
// accepted whatever os.Open would open, and tightening that here would change
// released behaviour in a phase whose contract forbids it. A caller that needs a
// stricter check — the fleet preflight requires a regular file, ADR 0072 §5.1 —
// performs it itself, before calling this.
func ReadFile(path string) (string, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the path is the operator's own input.
	if err != nil {
		return "", err
	}
	// Closed on every path, including the oversize refusal below.
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return "", ErrUnreadable
	}
	if info.IsDir() {
		return "", ErrIsDirectory
	}

	return Read(file)
}

// TrimOneLineEnding removes a single trailing "\r\n" or "\n", and nothing else.
//
// strings.TrimSpace is forbidden here. A leading or trailing space is legal
// password material, and removing it silently would turn a correct credential
// into a rejection — the single most misleading outcome this tool can produce,
// because it accuses the operator's secret store of being wrong. One trailing
// newline goes because every editor and `echo` adds one; a second one is the
// operator's data (ADR 0049 section 3).
//
// An embedded NUL is not touched, and neither is a second line. ADR 0072
// section 12 records both as the behaviour that exists today and declines to
// change either, because tightening released input handling is a decision for
// ADR 0049 and for all four leaf commands at once.
func TrimOneLineEnding(s string) string {
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2]
	case strings.HasSuffix(s, "\n"):
		return s[:len(s)-1]
	default:
		return s
	}
}

// OpenReason reduces a filesystem error to its cause, naming nothing else.
//
// Shared so that two callers describe the same failure with the same word. The
// path is not included: each caller already names it, and repeating it produces
// the message that says the path twice.
func OpenReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "no such file"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "unreadable"
	}
}
