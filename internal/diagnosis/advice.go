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
// ADR 0082 section 2.1 puts both in one type because they share every field and
// a reader tells them apart by this discriminator. Two types would duplicate
// validation, marshalling and redaction, and would hand a consumer two arrays.
//
// The zero AdviceKind is AdviceKindUnspecified.
type AdviceKind uint8

const (
	// AdviceKindUnspecified is the zero value and is not a kind.
	AdviceKindUnspecified AdviceKind = iota

	// AdviceKindNextEvidence is an observation that would discriminate between
	// the explanations that remain.
	//
	// It is the output a good diagnosis usually has. When two hypotheses remain,
	// the useful sentence is the one that separates them, not a remediation for
	// whichever happens to be listed first.
	AdviceKindNextEvidence

	// AdviceKindRemediation is a change to make, and it requires much stronger
	// evidence: CONFIRMED and HIGH, and nothing less (section 2.3 rule 1).
	AdviceKindRemediation
)

var adviceKindNames = [...]string{
	AdviceKindUnspecified:  "UNSPECIFIED",
	AdviceKindNextEvidence: "NEXT_EVIDENCE",
	AdviceKindRemediation:  "REMEDIATION",
}

// Valid reports whether k is a defined kind. AdviceKindUnspecified is not.
func (k AdviceKind) Valid() bool {
	return k != AdviceKindUnspecified && int(k) < len(adviceKindNames)
}

// String returns the symbolic name. It never fails.
func (k AdviceKind) String() string {
	if int(k) >= len(adviceKindNames) {
		return fmt.Sprintf("AdviceKind(%d)", uint8(k))
	}
	return adviceKindNames[k]
}

// SafetyClass is what taking the advice would cost, ordered by blast radius.
//
// The seven are frozen by ADR 0082 section 2.2. The first three change nothing
// and are the classes a diagnostic tool should overwhelmingly produce; the last
// three are **unreachable by any rule** and exist so that the prohibition is
// nameable and testable rather than merely absent.
//
// The zero SafetyClass is SafetyUnspecified.
type SafetyClass uint8

const (
	// SafetyUnspecified is the zero value and is not a class.
	SafetyUnspecified SafetyClass = iota

	// SafetyObserve means reading something that already exists.
	SafetyObserve

	// SafetyVerify means checking a claim, changing nothing.
	SafetyVerify

	// SafetyCompare means contrasting two observations.
	SafetyCompare

	// SafetyConfigChange means changing configuration, taking effect on reload
	// or reconnect.
	SafetyConfigChange

	// SafetyRestart means restarting a component. Unreachable: svcdoctor does
	// not tell anyone to restart anything.
	SafetyRestart

	// SafetyDisruptive means interrupting service or risking data. Unreachable.
	SafetyDisruptive

	// SafetySecurityWeakening means reducing a security property. Unreachable,
	// and the sharpest of the three: svcdoctor must never recommend disabling
	// the verification it exists to perform.
	SafetySecurityWeakening
)

var safetyClassNames = [...]string{
	SafetyUnspecified:       "UNSPECIFIED",
	SafetyObserve:           "OBSERVE",
	SafetyVerify:            "VERIFY",
	SafetyCompare:           "COMPARE",
	SafetyConfigChange:      "CONFIG_CHANGE",
	SafetyRestart:           "RESTART",
	SafetyDisruptive:        "DISRUPTIVE",
	SafetySecurityWeakening: "SECURITY_WEAKENING",
}

// Valid reports whether c is a defined class. SafetyUnspecified is not.
func (c SafetyClass) Valid() bool {
	return c != SafetyUnspecified && int(c) < len(safetyClassNames)
}

// String returns the symbolic name. It never fails.
func (c SafetyClass) String() string {
	if int(c) >= len(safetyClassNames) {
		return fmt.Sprintf("SafetyClass(%d)", uint8(c))
	}
	return safetyClassNames[c]
}

// Producible reports whether any rule may construct advice in this class.
//
// Three classes are false, permanently until an ADR says otherwise. They are in
// the vocabulary so that the report model can *classify* advice and so that a
// future phase which genuinely needs one has to add it deliberately, against a
// record. That friction is the point (ADR 0082 section 2.3 rule 2).
func (c SafetyClass) Producible() bool {
	switch c {
	case SafetyObserve, SafetyVerify, SafetyCompare, SafetyConfigChange:
		return true
	case SafetyUnspecified, SafetyRestart, SafetyDisruptive, SafetySecurityWeakening:
		return false
	}
	return false
}

// ChangesNothing reports whether taking the advice alters the target.
//
// The three read-only classes are the ceiling for anything below HIGH-confidence
// proof, which is what NewAdvice enforces.
func (c SafetyClass) ChangesNothing() bool {
	switch c {
	case SafetyObserve, SafetyVerify, SafetyCompare:
		return true
	default:
		return false
	}
}

// Advice is one suggested next action, with its kind and its cost.
//
// # Why it is here and not on domain.Recommendation
//
// ADR 0082 section 2.1 puts these fields on domain.Recommendation, which was
// built for it: its own doc comment says it is "a struct rather than a bare
// string so that the encoded form is an object from the outset, which lets
// fields such as a reference link or a remediation risk be added later". Adding
// them there is additive and needs no schema bump.
//
// It is still not what Phase 10.1a does, because adding a field to
// domain.Recommendation changes the canonical JSON of every report that carries
// one, and 10.1a's whole contract is that no report changes. So the vocabulary
// and the guardrails land here, unwired and tested, and 10.1b moves them onto
// the report type as ADR 0082 specifies. The guardrails are the part worth
// having early: they are what a rule author would otherwise be trusted to
// remember.
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
