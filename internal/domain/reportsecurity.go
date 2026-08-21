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

// ReportSecurity carries the facts a reader needs to interpret a report
// correctly.
//
// It is metadata, not a mechanism. It records what a run did; it performs no
// redaction and holds no secret. There is deliberately no security.Secret or
// security.Credential field, which is why this package needs no dependency on
// internal/security at all.
//
// # Why there is no redacted-field count
//
// docs/REPORT_SCHEMA.md section 9 also lists the number and categories of
// redacted fields. Those fields are absent here on purpose: no redactor exists,
// so any value this type could report would be a fabrication. A count of zero
// would read as "nothing sensitive was present" rather than "nothing was
// examined". They arrive with structural redaction, which can populate them
// honestly.
//
// The zero ReportSecurity is invalid. Use NewReportSecurity.
type ReportSecurity struct {
	outputMode                  OutputMode
	tlsVerificationDisabled     bool
	credentialForwardingEnabled bool
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

// OutputMode returns which form of report was produced.
func (s ReportSecurity) OutputMode() OutputMode { return s.outputMode }

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
func (s ReportSecurity) MarshalJSON() ([]byte, error) {
	if s.IsZero() {
		return nil, fmt.Errorf("%w: zero ReportSecurity", ErrInvalidValue)
	}
	return json.Marshal(struct {
		OutputMode                  OutputMode `json:"outputMode"`
		TLSVerificationDisabled     bool       `json:"tlsVerificationDisabled"`
		CredentialForwardingEnabled bool       `json:"credentialForwardingEnabled"`
	}{
		OutputMode:                  s.outputMode,
		TLSVerificationDisabled:     s.tlsVerificationDisabled,
		CredentialForwardingEnabled: s.credentialForwardingEnabled,
	})
}
