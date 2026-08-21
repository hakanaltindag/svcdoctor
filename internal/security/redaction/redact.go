package redaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ErrRedaction reports that a report could not be transformed safely.
//
// Redaction fails closed. There is no partially redacted result: either the
// whole report is rebuilt safely or nothing is returned, because a caller who
// received a half-transformed report would share it.
var ErrRedaction = errors.New("report redaction failed")

// Redact returns a shareable form of a local report.
//
// The input is not modified and remains LOCAL_FULL. The result is a new report
// built through the ordinary domain constructors, so it satisfies every report
// invariant, and its summary is re-derived rather than copied.
//
// Redaction is idempotent. A report that is already SHAREABLE_REDACTED is
// returned unchanged rather than transformed again, so pseudonyms are never
// pseudonymized into host-002 and calling this defensively is safe.
//
// What changes: hostnames, IP addresses, endpoint references, the target, the
// vantage host, evidence identifiers, and any of those values appearing inside
// prose. What does not change: layers, states, failure classes, steps, graph
// topology, finding codes, kinds, severities, confidences, timings, and the
// derived summary's diagnostic figures.
func Redact(report domain.Report) (domain.Report, error) {
	if report.IsZero() {
		return domain.Report{}, fmt.Errorf("%w: cannot redact the zero Report", ErrRedaction)
	}
	if report.Security().OutputMode() == domain.OutputModeShareableRedacted {
		return report, nil
	}

	t := newTable(collect(report))

	target, err := redactTarget(t, report.Target())
	if err != nil {
		return domain.Report{}, err
	}
	vantage, err := redactVantage(t, report.Vantage())
	if err != nil {
		return domain.Report{}, err
	}
	graph, err := redactGraph(t, report.Graph())
	if err != nil {
		return domain.Report{}, err
	}
	findings, err := redactFindings(t, report.Findings())
	if err != nil {
		return domain.Report{}, err
	}

	security, err := domain.NewShareableReportSecurity(report.Security(), t.counts())
	if err != nil {
		return domain.Report{}, fmt.Errorf("%w: %w", ErrRedaction, err)
	}

	out, err := domain.NewReport(domain.ReportInput{
		Run:      report.Run(),
		Target:   target,
		Vantage:  vantage,
		Graph:    graph,
		Findings: findings,
		Security: security,
	})
	if err != nil {
		return domain.Report{}, fmt.Errorf("%w: %w", ErrRedaction, err)
	}

	if err := verifyNoResidual(t, out); err != nil {
		return domain.Report{}, err
	}
	return out, nil
}

// collect gathers every identifying value the report carries structurally.
//
// Collection is separate from assignment so that pseudonym numbering depends on
// the set of values, not on the order they were found.
func collect(report domain.Report) (hosts, ips []string, ids []domain.EvidenceID) {
	classify(report.Target().Requested(), &hosts, &ips)
	for _, n := range report.Target().Normalized() {
		classify(n, &hosts, &ips)
	}
	if v := report.Vantage(); !v.IsZero() {
		classify(v.Host(), &hosts, &ips)
	}

	for _, e := range report.Graph().Nodes() {
		ids = append(ids, e.ID())
		classify(e.Subject().Ref(), &hosts, &ips)
		for _, v := range e.Attributes() {
			collectAttr(v, &hosts, &ips)
		}
	}

	for _, f := range report.Findings() {
		if s := f.Subject(); !s.IsZero() {
			classify(s.Ref(), &hosts, &ips)
		}
	}

	return hosts, ips, ids
}

// collectAttr gathers identifying values from an attribute.
//
// Only string-shaped values can carry identity. An integer, boolean, duration
// or timestamp cannot, which the closed AttrValue union makes checkable rather
// than assumed.
//
// A value is treated as identifying when it parses as an IP address or as a
// host:port reference. Both are structural tests, not pattern matching. A bare
// identifying string in some other shape is not recognized here; if it appears
// elsewhere in the report it is still replaced, and if it does not, it is
// preserved. See the package documentation.
func collectAttr(v domain.AttrValue, hosts, ips *[]string) {
	switch v.Kind() {
	case domain.AttrKindString:
		s, _ := v.Str()
		classifyAttrString(s, hosts, ips)
	case domain.AttrKindStringList:
		list, _ := v.StringList()
		for _, s := range list {
			classifyAttrString(s, hosts, ips)
		}
	case domain.AttrKindInvalid, domain.AttrKindInt, domain.AttrKindBool,
		domain.AttrKindDuration, domain.AttrKindTime:
		// Cannot carry identity.
	}
}

func classifyAttrString(s string, hosts, ips *[]string) {
	if s == "" {
		return
	}
	if _, err := netip.ParseAddr(s); err == nil {
		*ips = append(*ips, s)
		return
	}
	if host, _, hasPort := splitHostPort(s); hasPort && host != "" {
		classify(s, hosts, ips)
	}
}

func redactTarget(t *table, target domain.Target) (domain.Target, error) {
	normalized := target.Normalized()
	for i, n := range normalized {
		normalized[i] = t.endpointRef(n)
	}

	out, err := domain.NewTarget(t.endpointRef(target.Requested()), normalized...)
	if err != nil {
		return domain.Target{}, fmt.Errorf("%w: rebuilding target: %w", ErrRedaction, err)
	}
	return out, nil
}

// redactVantage keeps the kind of place and removes which one.
//
// A shareable report must still say the observations came from a local host,
// because every connectivity claim in it is only valid from that position. It
// must not say which host.
func redactVantage(t *table, v domain.Vantage) (domain.Vantage, error) {
	if v.Source() != domain.VantageSourceLocalHost {
		return domain.Vantage{}, fmt.Errorf(
			"%w: no shareable form is defined for vantage source %s", ErrRedaction, v.Source())
	}
	out, err := domain.NewLocalVantage(t.endpointRef(v.Host()))
	if err != nil {
		return domain.Vantage{}, fmt.Errorf("%w: rebuilding vantage: %w", ErrRedaction, err)
	}
	return out, nil
}

// redactGraph rebuilds the graph with pseudonymized nodes and remapped
// identifiers, preserving topology exactly.
func redactGraph(t *table, g domain.Graph) (domain.Graph, error) {
	b := domain.NewGraphBuilder()

	for _, e := range g.Nodes() {
		node, err := redactEvidence(t, e)
		if err != nil {
			return domain.Graph{}, err
		}
		if err := b.AddEvidence(node); err != nil {
			return domain.Graph{}, fmt.Errorf("%w: rebuilding graph: %w", ErrRedaction, err)
		}
	}

	// Relationships are re-added after every node exists, because the builder
	// deliberately rejects forward references.
	for _, e := range g.Nodes() {
		child, err := t.id(e.ID())
		if err != nil {
			return domain.Graph{}, err
		}
		for _, p := range g.Parents(e.ID()) {
			parent, err := t.id(p)
			if err != nil {
				return domain.Graph{}, err
			}
			if err := b.AddParent(child, parent); err != nil {
				return domain.Graph{}, fmt.Errorf("%w: rebuilding parents: %w", ErrRedaction, err)
			}
		}
		for _, blk := range g.BlockedBy(e.ID()) {
			blocker, err := t.id(blk)
			if err != nil {
				return domain.Graph{}, err
			}
			if err := b.AddBlockedBy(child, blocker); err != nil {
				return domain.Graph{}, fmt.Errorf("%w: rebuilding blocked-by: %w", ErrRedaction, err)
			}
		}
	}

	out, err := b.Freeze()
	if err != nil {
		return domain.Graph{}, fmt.Errorf("%w: freezing redacted graph: %w", ErrRedaction, err)
	}
	return out, nil
}

func redactEvidence(t *table, e domain.Evidence) (domain.Evidence, error) {
	id, err := t.id(e.ID())
	if err != nil {
		return domain.Evidence{}, err
	}
	subject, err := redactSubject(t, e.Subject())
	if err != nil {
		return domain.Evidence{}, err
	}

	attributes := e.Attributes()
	for key, value := range attributes {
		attributes[key] = redactAttr(t, value)
	}

	out, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           id,
		Subject:      subject,
		Layer:        e.Layer(),
		Step:         e.Step(),
		State:        e.State(),
		FailureClass: e.FailureClass(),
		Attributes:   attributes,
		StartedAt:    e.StartedAt(),
		Duration:     e.Duration(),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: rebuilding evidence: %w", ErrRedaction, err)
	}
	return out, nil
}

// redactSubject keeps the kind and replaces the identifying reference.
func redactSubject(t *table, s domain.Subject) (domain.Subject, error) {
	if s.IsZero() {
		return domain.Subject{}, nil
	}

	ref := t.endpointRef(s.Ref())
	var (
		out domain.Subject
		err error
	)
	switch s.Kind() {
	case domain.SubjectKindEndpoint:
		out, err = domain.NewEndpointSubject(ref)
	case domain.SubjectKindTarget:
		out, err = domain.NewTargetSubject(ref)
	case domain.SubjectKindUnspecified:
		return domain.Subject{}, fmt.Errorf("%w: subject has no kind", ErrRedaction)
	default:
		return domain.Subject{}, fmt.Errorf(
			"%w: no shareable form is defined for subject kind %s", ErrRedaction, s.Kind())
	}
	if err != nil {
		return domain.Subject{}, fmt.Errorf("%w: rebuilding subject: %w", ErrRedaction, err)
	}
	return out, nil
}

// redactAttr replaces identifying values while preserving everything a
// diagnostic reader needs.
//
// Only string-shaped values are touched. A duration, timestamp, count or flag
// carries no identity and is passed through unchanged, which is what keeps a
// shareable report diagnostically useful.
func redactAttr(t *table, v domain.AttrValue) domain.AttrValue {
	switch v.Kind() {
	case domain.AttrKindString:
		s, _ := v.Str()
		return domain.StringAttr(t.attrValue(s))
	case domain.AttrKindStringList:
		list, _ := v.StringList()
		for i, s := range list {
			list[i] = t.attrValue(s)
		}
		return domain.StringListAttr(list...)
	case domain.AttrKindInvalid, domain.AttrKindInt, domain.AttrKindBool,
		domain.AttrKindDuration, domain.AttrKindTime:
		return v
	}
	return v
}

// attrValue replaces an attribute string when it is a known identifying value.
//
// Values that are not identifiers keep their exact text, so "NOERROR" and
// "TLSv1.3" survive redaction intact.
func (t *table) attrValue(s string) string {
	if s == "" {
		return s
	}
	if _, ok := t.ips[s]; ok {
		return t.ip(s)
	}
	if _, ok := t.hosts[s]; ok {
		return t.host(s)
	}
	if host, port, hasPort := splitHostPort(s); hasPort {
		if _, known := t.ips[host]; known {
			return joinHostPort(t.ip(host), port)
		}
		if _, known := t.hosts[host]; known {
			return joinHostPort(t.host(host), port)
		}
	}
	return s
}

func redactFindings(t *table, findings []domain.Finding) ([]domain.Finding, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	out := make([]domain.Finding, 0, len(findings))
	for _, f := range findings {
		subject, err := redactSubject(t, f.Subject())
		if err != nil {
			return nil, err
		}

		refs := f.EvidenceRefs()
		for i, ref := range refs {
			mapped, err := t.id(ref)
			if err != nil {
				return nil, err
			}
			refs[i] = mapped
		}

		recommendations := f.Recommendations()
		rebuilt := make([]domain.Recommendation, 0, len(recommendations))
		for _, r := range recommendations {
			nr, err := domain.NewRecommendation(t.text(r.Action()))
			if err != nil {
				return nil, fmt.Errorf("%w: rebuilding recommendation: %w", ErrRedaction, err)
			}
			rebuilt = append(rebuilt, nr)
		}

		redacted, err := domain.NewFinding(domain.FindingInput{
			Code:             f.Code(),
			Kind:             f.Kind(),
			Severity:         f.Severity(),
			Confidence:       f.Confidence(),
			Layer:            f.Layer(),
			Subject:          subject,
			Summary:          t.text(f.Summary()),
			Detail:           t.text(f.Detail()),
			EvidenceRefs:     refs,
			Recommendations:  rebuilt,
			VantageDependent: f.VantageDependent(),
			Discriminator:    t.text(f.Discriminator()),
		})
		if err != nil {
			return nil, fmt.Errorf("%w: rebuilding finding %s: %w", ErrRedaction, f.Code(), err)
		}
		out = append(out, redacted)
	}
	return out, nil
}

// verifyNoResidual is the safety net.
//
// It re-reads the finished report and fails if any value the transformation
// knew to be identifying still appears. It checks exact known values rather
// than scanning for patterns, so it cannot produce a false alarm and cannot be
// satisfied by output that merely looks clean.
//
// This is a last line of defence, not the redaction mechanism: the values were
// already replaced structurally before serialization. It exists so that a future
// field added to the report without a matching transformation fails loudly
// instead of shipping an identifier.
func verifyNoResidual(t *table, out domain.Report) error {
	encoded, err := marshalForScan(out)
	if err != nil {
		return err
	}

	for original := range t.hosts {
		if strings.Contains(encoded, original) {
			return fmt.Errorf("%w: a hostname survived redaction", ErrRedaction)
		}
	}
	for original := range t.ips {
		if strings.Contains(encoded, original) {
			return fmt.Errorf("%w: an IP address survived redaction", ErrRedaction)
		}
	}
	for original := range t.ids {
		if strings.Contains(encoded, string(original)) {
			return fmt.Errorf("%w: an evidence identifier survived redaction", ErrRedaction)
		}
	}
	return nil
}

// marshalForScan renders the report so the safety net can inspect every field
// at once, including any added later that this package does not know about.
//
// The offending value is never named in an error. Reporting "10.20.30.40 leaked"
// would put the identifier into a log line, which is where it was being kept out
// of in the first place.
func marshalForScan(out domain.Report) (string, error) {
	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("%w: encoding the redacted report: %w", ErrRedaction, err)
	}
	return string(encoded), nil
}
