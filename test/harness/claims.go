package harness

import (
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// assertFindings checks which conclusions the run reached.
func assertFindings(t T, s Subject, e Expectation) {
	t.Helper()
	present := codeSet(s.Report)

	for _, code := range e.RequireFindings {
		if !present[code] {
			t.Errorf("%s: %s is missing.\n\nFindings produced: %v",
				s.label(), code, codesOf(s.Report))
		}
	}
	for _, code := range e.ForbidFindings {
		if present[code] {
			t.Errorf("%s: %s was produced and must not be.\n\n"+
				"A forbidden finding is a conclusion the evidence does not support; "+
				"this is the assertion that keeps a neighbouring diagnosis from "+
				"quietly widening into this one.\n\nFindings produced: %v",
				s.label(), code, codesOf(s.Report))
		}
	}
	if e.FindingCount != nil {
		if got := s.Report.FindingCount(); got != *e.FindingCount {
			t.Errorf("%s: %d finding(s), want %d: %v",
				s.label(), got, *e.FindingCount, codesOf(s.Report))
		}
	}
}

// assertProse checks the wording every finding carries, plus any rendered
// surface the scenario supplied.
//
// # Why prose is asserted at all
//
// A finding code is a promise about a category; its prose is the claim an
// operator actually reads. Most of the ways svcdoctor could overclaim are
// available to prose while every code stays correct — "the password is wrong"
// under a code that means only "the endpoint rejected what was presented". So
// the forbidden-phrase list is the load-bearing half of a migrated scenario.
func assertProse(t T, s Subject, e Expectation) {
	t.Helper()
	if len(e.RequireProse) == 0 && len(e.ForbidProse) == 0 {
		return
	}
	haystack := strings.ToLower(prose(s.Report) + "\n" + s.Text)

	for _, phrase := range e.RequireProse {
		if !strings.Contains(haystack, strings.ToLower(phrase)) {
			t.Errorf("%s: the report never says %q.\n\n"+
				"The scenario requires this claim to be stated; a run that proves "+
				"something and does not say it is not useful.", s.label(), phrase)
		}
	}
	for _, phrase := range e.ForbidProse {
		if !strings.Contains(haystack, strings.ToLower(phrase)) {
			continue
		}
		t.Errorf("%s: the report says %q, which this scenario forbids.\n\n"+
			"%s", s.label(), phrase, forbiddenClaimContext(s.Report, phrase))
	}
}

// forbiddenClaimContext names which finding carried a forbidden phrase.
//
// It reports the finding's code and where in it the phrase appeared, and never
// the surrounding text. Prose can quote an endpoint's own words or an operator's
// identifier, and a failure message must not become the place those escape.
func forbiddenClaimContext(r domain.Report, phrase string) string {
	needle := strings.ToLower(phrase)
	for _, f := range r.Findings() {
		for label, text := range map[string]string{
			"summary": f.Summary(), "detail": f.Detail(),
			"recommendations": recommendations(f),
		} {
			if strings.Contains(strings.ToLower(text), needle) {
				return "It appears in " + f.Code().String() + "'s " + label + "."
			}
		}
	}
	return "It appears in the rendered output the scenario supplied."
}

func prose(r domain.Report) string {
	var b strings.Builder
	for _, f := range r.Findings() {
		b.WriteString(f.Summary())
		b.WriteByte('\n')
		b.WriteString(f.Detail())
		b.WriteByte('\n')
		b.WriteString(recommendations(f))
		b.WriteByte('\n')
	}
	return b.String()
}

func recommendations(f domain.Finding) string {
	var b strings.Builder
	for _, r := range f.Recommendations() {
		b.WriteString(r.Action())
		b.WriteByte('\n')
	}
	return b.String()
}

func codeSet(r domain.Report) map[domain.FindingCode]bool {
	out := map[domain.FindingCode]bool{}
	for _, f := range r.Findings() {
		out[f.Code()] = true
	}
	return out
}

func codesOf(r domain.Report) []domain.FindingCode {
	var out []domain.FindingCode
	for _, f := range r.Findings() {
		out = append(out, f.Code())
	}
	return out
}
