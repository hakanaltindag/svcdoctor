// Package local collects facts about the host svcdoctor is running on.
//
// It is the platform boundary, and it is deliberately tiny. The platform layer
// gathers environment context and produces nothing else: no diagnosis, no
// adapter logic, no protocol semantics. Orchestration collects platform context
// and diagnosis consumes only what reached the evidence graph
// (docs/ARCHITECTURE.md section 12).
//
// # Why the vantage is built here and not in the command
//
// A vantage is a *fact about where the run observed from*, and ADR 0012 makes it
// first class precisely because a connectivity finding is only valid from the
// point it was measured. Building it in the CLI would put a platform fact in an
// argument parser, and the next caller — a future daemon, a Kubernetes-aware
// run, a test harness — would each invent their own. One producer, one fact.
package local

import (
	"fmt"
	"os"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Vantage reports where this process is running from.
//
// The hostname is the only thing collected. It is what an operator reading a
// report needs in order to know whose network position produced it, and
// collecting more — interfaces, addresses, cloud metadata, a machine ID — would
// put identity into every report for no diagnostic gain.
//
// # It is safe under the shareable model
//
// internal/security/redaction pseudonymizes the vantage host like any other
// identity, and fails closed on a vantage source it has no shareable form for.
// So a hostname recorded here becomes host-NNN in a shared report rather than
// leaking, and that is a property of the redaction layer rather than a promise
// made here.
//
// A host that cannot name itself is not a diagnostic failure and not a reason to
// refuse a run, but it is not something to paper over either: an empty vantage
// would make every finding's "from this vantage point" meaningless, so the error
// is returned and the caller decides.
func Vantage() (domain.Vantage, error) {
	host, err := os.Hostname()
	if err != nil {
		return domain.Vantage{}, fmt.Errorf("reading the local hostname: %w", err)
	}
	vantage, err := domain.NewLocalVantage(host)
	if err != nil {
		return domain.Vantage{}, fmt.Errorf("building the local vantage: %w", err)
	}
	return vantage, nil
}
