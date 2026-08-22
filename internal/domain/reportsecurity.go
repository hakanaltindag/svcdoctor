package domain

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// OutputMode says which form of a report was produced.
//
// The two-value vocabulary is defined by docs/SECURITY.md and
// docs/REPORT_SCHEMA.md section 9. Both constants exist so the encoded shape is
// stable, but only OutputModeLocalFull can currently be constructed.
//
// The zero OutputMode is OutputModeUnspecified.
type OutputMode uint8

const (
	// OutputModeUnspecified is the zero value and is not a mode.
	OutputModeUnspecified OutputMode = iota

	// OutputModeLocalFull is an unredacted report for local use.
	OutputModeLocalFull

	// OutputModeShareableRedacted is a report safe to share, with sensitive
	// values removed or pseudonymized.
	//
	// It cannot be constructed yet. Structural redaction does not exist, so a
	// report labelled this way would be claiming a transformation that never
	// happened, and a reader would share it believing it was safe. See
	// NewReportSecurity.
	OutputModeShareableRedacted
)

// outputModeNames is indexed by OutputMode. Keep it aligned with the const block
// above; TestOutputModeNamesCoverAllModes fails if the two drift apart.
var outputModeNames = [...]string{
	OutputModeUnspecified:       "UNSPECIFIED",
	OutputModeLocalFull:         "LOCAL_FULL",
	OutputModeShareableRedacted: "SHAREABLE_REDACTED",
}

// Valid reports whether m is a defined mode. OutputModeUnspecified is not.
func (m OutputMode) Valid() bool {
	return m != OutputModeUnspecified && int(m) < len(outputModeNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (m OutputMode) String() string {
	if int(m) >= len(outputModeNames) {
		return "OutputMode(" + strconv.FormatUint(uint64(m), 10) + ")"
	}
	return outputModeNames[m]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (m OutputMode) MarshalJSON() ([]byte, error) {
	if !m.Valid() {
		return nil, fmt.Errorf("%w: OutputMode(%d)", ErrInvalidValue, uint8(m))
	}
	return []byte(strconv.Quote(outputModeNames[m])), nil
}

// RedactionCounts is how many values a shareable transformation replaced, by
// category.
//
// It is a struct rather than a map so the encoded form has a fixed shape and a
// fixed field order, with no key-ordering question and no missing keys.
//
// The counts describe what was removed, never what it was. They exist so a
// reader can tell that redaction happened and roughly what kind of thing it
// touched, which is what docs/REPORT_SCHEMA.md section 9 asks for.
//
// Identity is a separate category from Hostname because the two name different
// kinds of thing: a network peer, and a principal or named resource such as a
// role or a database. Merging them would make one figure that a reader cannot
// act on, and it would imply the two share a pseudonym namespace, which they do
// not. It does not distinguish a role from a database — the attribute key that
// carried the value already says which, and it survives redaction. See ADR 0037.
//
// Every category counts distinct values, never occurrences, so the figures say
// what kind of thing was removed and not how often it appeared.
type RedactionCounts struct {
	// Hostname counts DNS names replaced, wherever they appeared.
	Hostname int `json:"hostname"`
	// IPAddress counts IP literals replaced.
	IPAddress int `json:"ipAddress"`
	// EvidenceID counts evidence identifiers rewritten.
	EvidenceID int `json:"evidenceId"`
	// Prose counts human-readable fields in which at least one value was
	// replaced.
	Prose int `json:"prose"`
	// Identity counts declared logical identities replaced.
	Identity int `json:"identity"`
}

// Total returns how many replacements were counted.
func (c RedactionCounts) Total() int {
	return c.Hostname + c.IPAddress + c.EvidenceID + c.Prose + c.Identity
}

// ReportSecurity carries the facts a reader needs to interpret a report
// correctly.
//
// It is metadata, not a mechanism. It records what a run did and what a
// transformation removed; it performs no redaction itself and holds no secret.
// There is deliberately no security.Secret or security.Credential field, which
// is why this package needs no dependency on internal/security at all.
//
// The zero ReportSecurity is invalid. Use NewReportSecurity, or
// NewShareableReportSecurity for the output of a redaction.
type ReportSecurity struct {
	outputMode                  OutputMode
	tlsVerificationDisabled     bool
	credentialForwardingEnabled bool
	redactions                  RedactionCounts
}

// NewReportSecurity records how a run was configured.
//
// OutputModeShareableRedacted is rejected. Structural redaction is not
// implemented, so accepting it would let a report assert that sensitive values
// were removed when nothing removed them. The intended design is that a
// shareable report is produced later by transforming a local report, and this
// constructor starts accepting the mode when that transformation exists.
func NewReportSecurity(
	mode OutputMode, tlsVerificationDisabled, credentialForwardingEnabled bool,
) (ReportSecurity, error) {
	if !mode.Valid() {
		return ReportSecurity{}, fmt.Errorf("%w: output mode %s", ErrInvalidValue, mode)
	}
	if mode == OutputModeShareableRedacted {
		return ReportSecurity{}, fmt.Errorf(
			"%w: output mode %s cannot be produced yet because structural redaction is not implemented",
			ErrInvalidValue, mode)
	}
	return ReportSecurity{
		outputMode:                  mode,
		tlsVerificationDisabled:     tlsVerificationDisabled,
		credentialForwardingEnabled: credentialForwardingEnabled,
	}, nil
}

// NewShareableReportSecurity derives the security metadata of a redacted report.
//
// It takes the local report's metadata and the counts of what a transformation
// actually replaced, so the shareable report carries forward the same facts
// about how the run was configured while stating what was removed.
//
// The source must be a LOCAL_FULL value. That is what keeps the mode honest:
// the ordinary constructor refuses to produce SHAREABLE_REDACTED at all, and
// this one can only derive it from a real local report, alongside counts a
// caller has to have something to count.
//
// Counts must not be negative. All-zero counts are valid and mean a report held
// nothing identifying.
func NewShareableReportSecurity(from ReportSecurity, redactions RedactionCounts) (ReportSecurity, error) {
	if from.IsZero() {
		return ReportSecurity{}, fmt.Errorf(
			"%w: shareable security metadata requires the local report's metadata", ErrInvalidValue)
	}
	if from.outputMode != OutputModeLocalFull {
		return ReportSecurity{}, fmt.Errorf(
			"%w: shareable security metadata must derive from %s, got %s",
			ErrInvalidValue, OutputModeLocalFull, from.outputMode)
	}
	if redactions.Hostname < 0 || redactions.IPAddress < 0 ||
		redactions.EvidenceID < 0 || redactions.Prose < 0 || redactions.Identity < 0 {
		return ReportSecurity{}, fmt.Errorf(
			"%w: redaction counts must not be negative", ErrInvalidValue)
	}
	return ReportSecurity{
		outputMode:                  OutputModeShareableRedacted,
		tlsVerificationDisabled:     from.tlsVerificationDisabled,
		credentialForwardingEnabled: from.credentialForwardingEnabled,
		redactions:                  redactions,
	}, nil
}

// OutputMode returns which form of report was produced.
func (s ReportSecurity) OutputMode() OutputMode { return s.outputMode }

// Redactions returns how many values a shareable transformation replaced.
//
// It is all zeroes on a local report, where nothing was transformed.
func (s ReportSecurity) Redactions() RedactionCounts { return s.redactions }

// TLSVerificationDisabled reports whether the run ran with TLS verification off.
func (s ReportSecurity) TLSVerificationDisabled() bool { return s.tlsVerificationDisabled }

// CredentialForwardingEnabled reports whether credentials were allowed to reach
// endpoints found through topology discovery.
func (s ReportSecurity) CredentialForwardingEnabled() bool { return s.credentialForwardingEnabled }

// IsZero reports whether s is the invalid zero ReportSecurity.
func (s ReportSecurity) IsZero() bool { return s == ReportSecurity{} }

// MarshalJSON emits the security metadata as an object.
//
// The booleans are always present, because false is a statement about the run
// rather than an absent value.
//
// The redaction counts appear only on a shareable report. On a local report
// there was no transformation, and emitting zeroes would read as "nothing
// sensitive was present" rather than "nothing was removed".
func (s ReportSecurity) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return nil, fmt.Errorf("%w: zero ReportSecurity", ErrInvalidValue)
	}

	out := struct {
		OutputMode                  OutputMode       `json:"outputMode"`
		TLSVerificationDisabled     bool             `json:"tlsVerificationDisabled"`
		CredentialForwardingEnabled bool             `json:"credentialForwardingEnabled"`
		Redactions                  *RedactionCounts `json:"redactions,omitempty"`
	}{
		OutputMode:                  s.outputMode,
		TLSVerificationDisabled:     s.tlsVerificationDisabled,
		CredentialForwardingEnabled: s.credentialForwardingEnabled,
	}
	if s.outputMode == OutputModeShareableRedacted {
		out.Redactions = &s.redactions
	}

	return json.Marshal(out)
}
