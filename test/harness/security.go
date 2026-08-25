package harness

import (
	"encoding/json"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// assertSecurity checks the two security properties the migrated scenarios rely
// on: a secret never reaches a report, and a run never exceeds its credential
// budget.
func assertSecurity(t T, s Subject, e Expectation) {
	t.Helper()

	assertNoSecret(t, s, e)

	if e.MaxCredentialAttempts == nil {
		return
	}
	if s.CredentialAttempts == nil {
		t.Errorf("%s: a credential-attempt bound of %d was stated and the scenario "+
			"measured no count.\n\n"+
			"The bound is only as good as the measurement; supply "+
			"Subject.CredentialAttempts or drop the expectation.",
			s.label(), *e.MaxCredentialAttempts)
		return
	}
	if *s.CredentialAttempts > *e.MaxCredentialAttempts {
		t.Errorf("%s: %d credential-bearing attempt(s), want at most %d.\n\n"+
			"Every attempt is one the endpoint counts — an ACL log entry, a lockout "+
			"counter, a provider metric — so the bound is a property of the run and "+
			"not an implementation detail.",
			s.label(), *s.CredentialAttempts, *e.MaxCredentialAttempts)
	}
}

// assertNoSecret proves a value is absent from every report the scenario
// produced.
//
// # It searches the canonical serialization, not the prose
//
// A secret that reached an evidence attribute, a subject, a target or a finding
// reference would be invisible to a prose scan and entirely visible to anyone
// reading the JSON. Marshalling the report is what the product itself does, so
// this looks at exactly the bytes a reader would get.
//
// # It never prints what it found
//
// Not the secret, not the surrounding text, not the report. A leak assertion
// that dumps the leak on failure moves the secret from a report into CI logs,
// which is the same defect in a different file. The message says which document
// carried it and stops there.
func assertNoSecret(t T, s Subject, e Expectation) {
	t.Helper()
	if len(e.ForbidSecrets) == 0 {
		return
	}

	documents := []struct {
		name   string
		report domain.Report
	}{{"the canonical report", s.Report}}
	if s.Shareable != nil {
		documents = append(documents, struct {
			name   string
			report domain.Report
		}{"the shareable report", *s.Shareable})
	}

	for _, document := range documents {
		encoded, err := json.Marshal(document.report)
		if err != nil {
			t.Errorf("%s: encoding %s: %v", s.label(), document.name, err)
			continue
		}
		body := string(encoded)
		for _, secret := range e.ForbidSecrets {
			if secret == "" {
				t.Errorf("%s: an empty string was given as a forbidden secret, which "+
					"every document contains; this assertion would never fail", s.label())
				continue
			}
			if strings.Contains(body, secret) {
				t.Errorf("%s: a value this scenario marked secret appears in %s.\n\n"+
					"The value is not reproduced here on purpose. Look for the "+
					"credential this scenario presented.", s.label(), document.name)
			}
		}
	}
}
