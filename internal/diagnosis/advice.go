package diagnosis

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ErrUnsafeAdvice reports that a suggested next action is not one svcdoctor may
// give.
var ErrUnsafeAdvice = errors.New("unsafe advice")

// AdviceKind distinguishes an observation to take from a change to make.
//
// **It is an alias for domain.RecommendationKind, not a parallel vocabulary.**
// Phase 10.4B moved the enumeration down to internal/domain, because it is
// serialized into the canonical report and the package that owns the report
// model owns its wire spelling. An alias rather than a distinct type is the
// whole point: there is no mapping between the two, so there is nothing that can
// drift, and "every AdviceKind maps exactly" is true by identity rather than by
// a table somebody has to keep aligned.
//
// The names below are kept so that no rule and no test had to change.
//
// The zero AdviceKind is AdviceKindUnspecified.
type AdviceKind = domain.RecommendationKind

const (
	// AdviceKindUnspecified is the zero value and is not a kind.
	AdviceKindUnspecified = domain.RecommendationKindUnspecified

	// AdviceKindNextEvidence is an observation that would discriminate between
	// the explanations that remain.
	//
	// It is the output a good diagnosis usually has. When two hypotheses remain,
	// the useful sentence is the one that separates them, not a remediation for
	// whichever happens to be listed first.
	AdviceKindNextEvidence = domain.RecommendationKindNextEvidence

	// AdviceKindRemediation is a change to make, and it requires much stronger
	// evidence: CONFIRMED and HIGH, and nothing less (section 2.3 rule 1).
	AdviceKindRemediation = domain.RecommendationKindRemediation
)

// SafetyClass is what taking the advice would cost, ordered by blast radius.
//
// **An alias for domain.SafetyClass**, for the reason AdviceKind is one. The
// seven values, Producible and ChangesNothing all moved down with the type, and
// the move strengthened them: Producible now runs at the report boundary in
// domain.NewClassifiedRecommendation, so the three unreachable classes are
// unreachable on every construction path rather than only on this one.
//
// The zero SafetyClass is SafetyUnspecified.
type SafetyClass = domain.SafetyClass

const (
	// SafetyUnspecified is the zero value and is not a class.
	SafetyUnspecified = domain.SafetyUnspecified

	// SafetyObserve means reading something that already exists.
	SafetyObserve = domain.SafetyObserve

	// SafetyVerify means checking a claim, changing nothing.
	SafetyVerify = domain.SafetyVerify

	// SafetyCompare means contrasting two observations.
	SafetyCompare = domain.SafetyCompare

	// SafetyConfigChange means changing configuration, taking effect on reload
	// or reconnect.
	SafetyConfigChange = domain.SafetyConfigChange

	// SafetyRestart means restarting a component. Unreachable: svcdoctor does
	// not tell anyone to restart anything.
	SafetyRestart = domain.SafetyRestart

	// SafetyDisruptive means interrupting service or risking data. Unreachable.
	SafetyDisruptive = domain.SafetyDisruptive

	// SafetySecurityWeakening means reducing a security property. Unreachable,
	// and the sharpest of the three: svcdoctor must never recommend disabling
	// the verification it exists to perform.
	SafetySecurityWeakening = domain.SafetySecurityWeakening
)

// Advice is one suggested next action, with its kind and its cost.
//
// # Its relationship to domain.Recommendation, since Phase 10.4B
//
// ADR 0082 section 2.1 put these fields on domain.Recommendation. Phase 10.1a
// deferred the move because it changes the canonical JSON of every report that
// carries a recommendation, and 10.1a's contract was that no report changes;
// 10.1b, 10.2 and 10.3 each deferred it again, and the four fields were computed,
// validated and then discarded at the report boundary the whole time.
//
// **Phase 10.4B completed the move.** Advice remains the *construction* type —
// it is where an input is validated and where AdmitAdvice's confidence gate is
// applied — and domain.Recommendation is the *report* type it projects into,
// through the single path Advice.Recommendation. Nothing is lost between them,
// which TestAdviceProjectionPreservesEveryField pins field by field.
//
// The two are not redundant. Advice can be refused; a Recommendation that exists
// has already survived every refusal.
//
// The zero Advice is invalid. Use NewAdvice.
type Advice struct {
	kind            AdviceKind
	safety          SafetyClass
	action          string
	rationale       string
	selfCollectable bool
}

// AdviceInput carries the values NewAdvice validates.
type AdviceInput struct {
	// Kind says whether this is an observation to take or a change to make.
	Kind AdviceKind

	// Safety is what taking it would cost.
	Safety SafetyClass

	// Action is one line of human-readable text. Never a command to execute.
	Action string

	// Rationale says why this observation discriminates, or why this change
	// follows from the evidence.
	Rationale string

	// SelfCollectable reports whether svcdoctor could take this observation
	// itself in some run. It is deliberately often false, and saying so is more
	// useful than implying svcdoctor already looked.
	//
	// True does not mean svcdoctor will collect it. Diagnosis performs no I/O
	// and there is no automatic collection (ADR 0078 section 2.6); it means a
	// differently configured run could — "re-run with a larger execution
	// budget" is the shape of it.
	//
	// It is meaningless on a remediation, and NewAdvice rejects it there.
	SelfCollectable bool
}

// NewAdvice validates in and returns the resulting Advice.
//
// It enforces the guardrails of ADR 0082 section 2.3 that can be enforced
// without a finding in hand. The one that needs a finding — remediation requires
// CONFIRMED and HIGH — is AdmitAdvice.
//
//  1. The three high-blast-radius classes are refused outright.
//  2. A next-evidence recommendation must change nothing, so its class is one of
//     the three read-only ones.
//  3. The action must not be an executable command.
func NewAdvice(in AdviceInput) (Advice, error) {
	if !in.Kind.Valid() {
		return Advice{}, fmt.Errorf("%w: advice kind %s", domain.ErrInvalidValue, in.Kind)
	}
	if !in.Safety.Valid() {
		return Advice{}, fmt.Errorf("%w: safety class %s", domain.ErrInvalidValue, in.Safety)
	}
	if !in.Safety.Producible() {
		return Advice{}, fmt.Errorf(
			"%w: no rule may produce %s advice; the class exists so the prohibition is "+
				"nameable, and lifting it is an ADR (ADR 0082 section 2.3 rule 2)",
			ErrUnsafeAdvice, in.Safety)
	}
	if in.Kind == AdviceKindNextEvidence && !in.Safety.ChangesNothing() {
		return Advice{}, fmt.Errorf(
			"%w: %s advice is classified %s; an observation that changes the target is "+
				"a remediation wearing the wrong label (ADR 0082 section 2.4)",
			ErrUnsafeAdvice, in.Kind, in.Safety)
	}
	if in.Kind == AdviceKindRemediation && in.SelfCollectable {
		return Advice{}, fmt.Errorf(
			"%w: SelfCollectable describes an observation svcdoctor could take, and "+
				"svcdoctor takes no remediation at all", ErrUnsafeAdvice)
	}
	if err := ValidateActionText(in.Action); err != nil {
		return Advice{}, err
	}
	if strings.TrimSpace(in.Rationale) == "" {
		return Advice{}, fmt.Errorf(
			"%w: advice must say why; a suggestion with no stated reason cannot be "+
				"reviewed or rejected", domain.ErrInvalidValue)
	}

	return Advice{
		kind:            in.Kind,
		safety:          in.Safety,
		action:          in.Action,
		rationale:       in.Rationale,
		selfCollectable: in.SelfCollectable,
	}, nil
}

// Kind returns whether this is an observation or a change.
func (a Advice) Kind() AdviceKind { return a.kind }

// Safety returns what taking it would cost.
func (a Advice) Safety() SafetyClass { return a.safety }

// Action returns the one-line suggestion.
func (a Advice) Action() string { return a.action }

// Rationale returns why it discriminates, or why it follows.
func (a Advice) Rationale() string { return a.rationale }

// SelfCollectable reports whether svcdoctor could take this observation itself.
func (a Advice) SelfCollectable() bool { return a.selfCollectable }

// IsZero reports whether a is the invalid zero Advice.
func (a Advice) IsZero() bool { return a.kind == AdviceKindUnspecified && a.action == "" }

// AdmitAdvice reports whether a finding of this strength may carry this advice.
//
// This is the confidence gate of ADR 0082 section 2.3 rule 1, and it is the
// guardrail with teeth: a diagnostic tool that says "restart the broker" on weak
// evidence is worse than one that says nothing, and the pressure to emit
// remediation grows exactly as the reasoning gets better.
//
//	REMEDIATION      requires CONFIRMED and HIGH — nothing less
//	NEXT_EVIDENCE    always admissible; it changes nothing by construction
//
// A LOW-confidence hypothesis may therefore carry only OBSERVE, VERIFY or
// COMPARE, which NewAdvice has already narrowed next-evidence advice to.
func AdmitAdvice(kind domain.FindingKind, confidence domain.Confidence, advice Advice) error {
	if advice.IsZero() {
		return fmt.Errorf("%w: the zero Advice", domain.ErrInvalidValue)
	}
	if !kind.Valid() {
		return fmt.Errorf("%w: finding kind %s", domain.ErrInvalidValue, kind)
	}
	if !confidence.Valid() {
		return fmt.Errorf("%w: confidence %s", domain.ErrInvalidValue, confidence)
	}
	if advice.kind != AdviceKindRemediation {
		return nil
	}

	if kind != domain.FindingKindConfirmed || confidence != domain.ConfidenceHigh {
		return fmt.Errorf(
			"%w: a REMEDIATION needs a CONFIRMED finding at HIGH confidence, and this "+
				"one is %s at %s; below that the correct output is the observation "+
				"that would settle it (ADR 0082 section 2.3 rule 1)",
			ErrUnsafeAdvice, kind, confidence)
	}
	return nil
}

// commandWords are the leading tokens that make a line something to paste.
//
// The list is not a security boundary and does not try to be exhaustive — an
// action is prose, and a determined author could write a command that evades any
// list. It is a guard against the ordinary drift: a helpful contributor pasting
// the command they used while debugging. ADR 0082 section 2.3 rule 3 is the
// rule; this is what makes it fail a build rather than a review.
//
// # Why no service's own tool is named here
//
// The first version of this list held `psql`, `mysql`, `redis-cli` and
// `rabbitmqctl`, and the Phase 10.1a vocabulary guard rejected it — correctly.
// This package is the generic core, and a service's tooling is that service's
// vocabulary (ADR 0080 section 2.3). The entries below are general-purpose shell
// and operations commands, which are not any service's knowledge.
//
// The residual gap is recorded rather than argued away: a bare
// "<service-tool> <subcommand>" line with no flag and no metacharacter is not
// caught here. Catching it needs the tool's name, and the only layer that knows
// it is the service's own rule package — which is exactly where such a
// recommendation would be written. Every recommendation the tree actually
// produces is checked against this validator by
// TestDIAG036EveryProducedRecommendationIsAlreadySafe.
var commandWords = map[string]struct{}{
	"apt": {}, "aws": {}, "brew": {}, "cat": {}, "chmod": {}, "chown": {},
	"curl": {}, "dig": {}, "docker": {}, "echo": {}, "gcloud": {}, "grep": {},
	"helm": {}, "kubectl": {}, "ln": {}, "mv": {}, "nc": {}, "netstat": {},
	"nslookup": {}, "openssl": {}, "ping": {}, "rm": {}, "scp": {}, "sed": {},
	"service": {}, "sh": {}, "ssh": {}, "sudo": {}, "systemctl": {},
	"tcpdump": {}, "telnet": {}, "terraform": {}, "traceroute": {}, "wget": {},
}

// sqlWords are the leading tokens that make a line something to run on a server.
//
// A SQL statement in a report is a command in every sense that matters, and
// svcdoctor runs no SQL by design.
//
// # Why the match is on capitalization rather than on the word
//
// Every one of these is also an ordinary English verb, and matching the word
// alone rejects correct prose. "Grant the diagnostic identity permission to run
// PING" is advice about an authorization; "GRANT ... TO ..." is a statement.
// Existing recommendations in this tree open with "Grant" and with "Verify", and
// they are right to.
//
// So a leading SQL keyword is flagged when it is written the way SQL is written
// — in capitals — and a lower-case "select" is flagged only when the rest of the
// line carries the structure that makes it a query. That admits the English and
// refuses the statement, which is the distinction the rule is actually about.
var sqlWords = map[string]struct{}{
	"alter": {}, "create": {}, "delete": {}, "drop": {}, "grant": {},
	"insert": {}, "revoke": {}, "select": {}, "truncate": {}, "update": {},
}

// shellMetacharacters are the characters that make a line composable.
//
// A pipe, a redirect, a substitution or a line break turns a sentence into
// something a shell would act on. None of them has a place in one line of
// English advice.
//
// # Why ";" is not here
//
// It was, and it rejected two correct recommendations whose semicolons are
// ordinary English punctuation joining two independent clauses. A semicolon does
// separate shell statements, but every construct it would separate has to start
// with something, and that something is what the leading-token and flag checks
// below are for. Keeping it would have meant rewording prose that is not a
// command in order to satisfy a rule about commands.
const shellMetacharacters = "|&<>$`\\\n\r\t"

// ValidateActionText rejects an action that is an executable command.
//
// ADR 0082 section 2.3 rule 3 is permanent and it is not about tidiness: a
// command in a report is a command someone pastes, and it matters most in the
// shareable projection, where the reader may not be the operator who ran it.
// svcdoctor changes nothing by design.
//
// It is exported so that the check can be run against the recommendations
// production rules already emit. Phase 10.1a does exactly that — see
// TestDIAG036EveryProducedRecommendationIsAlreadySafe — which is how a guard
// that will be enforced in 10.1b is shown to be adoptable without changing a
// single existing string.
func ValidateActionText(action string) error {
	if strings.TrimSpace(action) == "" {
		return fmt.Errorf("%w: an action must not be blank", domain.ErrInvalidValue)
	}
	if strings.TrimSpace(action) != action {
		return fmt.Errorf(
			"%w: an action must not have leading or trailing whitespace",
			domain.ErrInvalidValue)
	}
	if idx := strings.IndexAny(action, shellMetacharacters); idx >= 0 {
		return fmt.Errorf(
			"%w: the action contains %q, which makes it something a shell would act "+
				"on; a recommendation is a sentence, never a command (ADR 0082 "+
				"section 2.3 rule 3)", ErrUnsafeAdvice, action[idx:idx+1])
	}

	// A short flag is the generic signal that survives not knowing any tool's
	// name: "psql -h host -U user" and "openssl s_client -connect host" are
	// command invocations whatever the binary is called.
	//
	// Only single-hyphen flags count. A double-hyphen token in this repository's
	// advice is svcdoctor naming one of its **own** options — "supply
	// --password-file", "use --tls require" — which is documentation about the
	// diagnostic tool rather than a change to make on the target, and svcdoctor
	// changes nothing when it runs. A hyphenated English word is unaffected
	// either way, because its hyphen is inside it.
	for _, token := range strings.Fields(action) {
		if strings.HasPrefix(token, "-") && !strings.HasPrefix(token, "--") {
			return fmt.Errorf(
				"%w: the action contains the flag %q, which makes it read as a command "+
					"invocation; state what to look at, not what to type (ADR 0082 "+
					"section 2.3 rule 3)", ErrUnsafeAdvice, token)
		}
	}

	first := action
	if space := strings.IndexFunc(action, unicode.IsSpace); space >= 0 {
		first = action[:space]
	}
	trimmed := strings.Trim(first, ".,:;\"'()")
	lowered := strings.ToLower(trimmed)
	if _, banned := commandWords[lowered]; banned {
		return fmt.Errorf(
			"%w: the action begins with %q, which reads as a command to run; state "+
				"what to look at, not what to type (ADR 0082 section 2.3 rule 3)",
			ErrUnsafeAdvice, lowered)
	}
	if looksLikeSQL(trimmed, lowered, action) {
		return fmt.Errorf(
			"%w: the action begins with the SQL keyword %q; svcdoctor runs no SQL and "+
				"puts none in a report (ADR 0082 section 2.3 rule 3)",
			ErrUnsafeAdvice, trimmed)
	}
	return nil
}

// looksLikeSQL reports whether an action opens a SQL statement rather than an
// English sentence.
//
// See the note on sqlWords for why the word alone is not enough. Two shapes are
// refused: a leading keyword written in capitals, which is how SQL is written
// and is not how a sentence begins, and a lower-case "select" followed by the
// "from" that makes it a query.
func looksLikeSQL(first, lowered, action string) bool {
	if _, keyword := sqlWords[lowered]; !keyword {
		return false
	}
	if first == strings.ToUpper(first) && first != "" {
		return true
	}
	return lowered == "select" && strings.Contains(strings.ToLower(action), " from ")
}

// Recommendation projects the advice into the canonical report type.
//
// **This is the one production conversion from Advice to domain.Recommendation.**
// Before Phase 10.4B there were two, one copied into each service package that
// had classified advice, and both dropped four of the five fields on the way —
// which is the defect this phase exists to close. Two independent mappings can
// drift; one cannot, and TestExactlyOneAdviceProjectionPathExists fails the build
// if a second appears.
//
// It preserves all five fields exactly. The domain constructor re-validates
// rather than trusting this one, which is deliberate: the guardrails belong at
// the boundary they protect, not at the last place that happened to touch the
// value.
func (a Advice) Recommendation() (domain.Recommendation, error) {
	if a.IsZero() {
		return domain.Recommendation{}, fmt.Errorf("%w: the zero Advice", domain.ErrInvalidValue)
	}
	return domain.NewClassifiedRecommendation(domain.RecommendationInput{
		Action:          a.action,
		Kind:            a.kind,
		Safety:          a.safety,
		Rationale:       a.rationale,
		SelfCollectable: a.selfCollectable,
	})
}

// Recommend validates one suggestion and returns what a report may carry.
//
// It is the whole guarded path in one call: construct, admit against the
// finding's strength, project. A rejected suggestion yields **no recommendation
// at all** — emitting an unclassified string because the classified one was
// refused would be the guardrail deleting itself.
//
// # Why this is generic and not per service
//
// Until Phase 10.4B each service package held its own `projectAdvice` copy, and
// ADR 0084 section 9 defended the duplication on the ground that an exported
// helper here "would put a *findings* constructor in the package whose whole
// contract is that it knows no service's claims". That reasoning does not reach
// this function: it constructs no finding, names no service, and returns a
// generic report type from generic inputs. What the duplication actually bought
// was two places for the same projection to lose the same four fields.
//
// The caller supplies the finding's kind and confidence because AdmitAdvice
// needs them and a rule knows them; nothing here reads a graph.
func Recommend(
	in AdviceInput, kind domain.FindingKind, confidence domain.Confidence,
) []domain.Recommendation {
	advice, err := NewAdvice(in)
	if err != nil {
		return nil
	}
	if err := AdmitAdvice(kind, confidence, advice); err != nil {
		return nil
	}
	recommendation, err := advice.Recommendation()
	if err != nil {
		return nil
	}
	return []domain.Recommendation{recommendation}
}
