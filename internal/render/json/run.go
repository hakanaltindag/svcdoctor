package json

import (
	stdjson "encoding/json"
	"fmt"
	"io"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// WriteRun emits the canonical aggregate document.
//
// It reimplements nothing. json.Marshal calls domain.RunReport's own
// MarshalJSON, which in turn calls each embedded report's — so the aggregate
// cannot drift from either schema, and a target's report inside a run is
// byte-identical to the same report emitted on its own.
//
// # It never serializes what the aggregate does not hold
//
// No raw configuration, no credential reference, no environment variable name,
// no credential file path, no resolved secret, no runner state. That is not
// enforced here: the aggregate has no field for any of them, so there is nothing
// for this function to omit. Canary tests prove it over the rendered bytes
// rather than trusting the shape.
//
// **Redaction happens before this, never after.** A caller that wants a
// shareable document derives one with redaction.RedactRun and passes the result.
// Rewriting the text afterwards — replacing hostnames in a finished JSON string
// — is the approach ADR 0018 refuses, because a value the pattern missed is a
// value that ships.
//
// # The encoding happens before the first byte is written
//
// A document that failed to encode must not leave half an artifact on stdout, so
// the whole thing is built in memory and written once. ADR 0073 section 11.5
// bounds its size through the target ceiling.
func WriteRun(w io.Writer, report domain.RunReport) error {
	if w == nil {
		return fmt.Errorf("writing the run report: no writer")
	}

	encoded, err := stdjson.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding the run report: %w", err)
	}

	encoded = append(encoded, '\n')
	if _, err := w.Write(encoded); err != nil {
		return fmt.Errorf("writing the run report: %w", err)
	}
	return nil
}
