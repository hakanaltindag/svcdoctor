package redaction

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// table maps identifying values to stable pseudonyms for one transformation.
//
// Assignment is a separate step from use: every value is collected first, then
// sorted, then numbered. Numbering on first encounter would tie a pseudonym to
// traversal order, so adding a rule or reordering a graph walk later would
// silently renumber an existing report.
//
// The table lives for one call. There is no global state, nothing persists
// between reports, and the same value in two different reports may receive
// different pseudonyms. That is deliberate: a stable cross-report pseudonym
// would let someone correlate two shared reports from the same environment.
type table struct {
	hosts map[string]string
	ips   map[string]string
	ids   map[domain.EvidenceID]domain.EvidenceID

	// prose holds the replacements applied to free text, longest source value
	// first so that a longer value is never partly rewritten by a shorter one
	// it contains.
	prose []replacement

	// usedHosts, usedIPs and usedIDs record which values were actually
	// replaced, so the reported counts describe the transformation that
	// happened rather than the values that were collected.
	usedHosts map[string]struct{}
	usedIPs   map[string]struct{}
	usedIDs   map[domain.EvidenceID]struct{}

	proseFields int
}

type replacement struct {
	from string
	to   string
}

// newTable assigns pseudonyms to the collected values.
//
// hosts and ips are the distinct identifying values found structurally; ids are
// every evidence identifier in the graph.
func newTable(hosts, ips []string, ids []domain.EvidenceID) *table {
	t := &table{
		hosts:     make(map[string]string, len(hosts)),
		ips:       make(map[string]string, len(ips)),
		ids:       make(map[domain.EvidenceID]domain.EvidenceID, len(ids)),
		usedHosts: make(map[string]struct{}),
		usedIPs:   make(map[string]struct{}),
		usedIDs:   make(map[domain.EvidenceID]struct{}),
	}

	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	for i, h := range hosts {
		t.hosts[h] = fmt.Sprintf("host-%03d", i+1)
	}

	slices.Sort(ips)
	ips = slices.Compact(ips)
	for i, ip := range ips {
		t.ips[ip] = fmt.Sprintf("ip-%03d", i+1)
	}

	slices.Sort(ids)
	ids = slices.Compact(ids)
	for i, id := range ids {
		t.ids[id] = domain.EvidenceID(fmt.Sprintf("evidence-%03d", i+1))
	}

	for from, to := range t.hosts {
		t.prose = append(t.prose, replacement{from: from, to: to})
	}
	for from, to := range t.ips {
		t.prose = append(t.prose, replacement{from: from, to: to})
	}
	for from, to := range t.ids {
		t.prose = append(t.prose, replacement{from: string(from), to: string(to)})
	}
	// Longest first, then lexical, so the result does not depend on map order.
	slices.SortFunc(t.prose, func(a, b replacement) int {
		if d := len(b.from) - len(a.from); d != 0 {
			return d
		}
		return strings.Compare(a.from, b.from)
	})

	return t
}

// host returns the pseudonym for a DNS name, recording that it was replaced.
func (t *table) host(name string) string {
	p, ok := t.hosts[name]
	if !ok {
		return name
	}
	t.usedHosts[name] = struct{}{}
	return p
}

// ip returns the pseudonym for an IP literal, recording that it was replaced.
func (t *table) ip(addr string) string {
	p, ok := t.ips[addr]
	if !ok {
		return addr
	}
	t.usedIPs[addr] = struct{}{}
	return p
}

// id returns the pseudonym for an evidence identifier.
//
// The error names the identifier because reaching this branch means the graph
// contained a node that collection missed, which is a defect in this package
// rather than a leak path: the caller is the redactor, which fails closed and
// returns no report.
func (t *table) id(original domain.EvidenceID) (domain.EvidenceID, error) {
	p, ok := t.ids[original]
	if !ok {
		return "", fmt.Errorf("%w: an evidence identifier was never collected", ErrRedaction)
	}
	t.usedIDs[original] = struct{}{}
	return p, nil
}

// counts reports what the transformation replaced.
//
// Each category counts distinct values, not occurrences. "Two hostnames were
// removed" is what a reader can act on, and it is also the safer figure to
// publish: an occurrence count would describe how often each host appeared,
// which is structural information about the environment. Prose is the exception
// and counts fields, because a rewritten sentence has no natural value count.
func (t *table) counts() domain.RedactionCounts {
	return domain.RedactionCounts{
		Hostname:   len(t.usedHosts),
		IPAddress:  len(t.usedIPs),
		EvidenceID: len(t.usedIDs),
		Prose:      t.proseFields,
	}
}

// text replaces every known identifying value inside free-form prose.
//
// This is exact replacement of values the report was already found to contain
// structurally, not pattern matching. Prose that mentions a host the report does
// not otherwise carry cannot be recognized; see the package documentation.
func (t *table) text(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, r := range t.prose {
		out = strings.ReplaceAll(out, r.from, r.to)
	}
	if out != s {
		t.proseFields++
	}
	return out
}

// endpointRef rewrites a "host" or "host:port" reference, keeping the port.
//
// A port is diagnostic information rather than an identifier: knowing a check
// targeted 9092 says which protocol was expected, not who was running it.
func (t *table) endpointRef(ref string) string {
	host, port, hasPort := splitHostPort(ref)
	if !hasPort {
		return t.value(ref)
	}
	return joinHostPort(t.value(host), port)
}

// value rewrites a bare identifying value, choosing the right category.
func (t *table) value(v string) string {
	if _, err := netip.ParseAddr(v); err == nil {
		return t.ip(v)
	}
	return t.host(v)
}

// splitHostPort separates a trailing ":port" from a reference.
//
// It deliberately does not use net.SplitHostPort. internal/security/endpoint.go
// made the same choice for the same reason: importing net would link the network
// stack into a package that only needs the bracketing rule. A host containing a
// colon is an IPv6 literal, which is bracketed when a port follows.
func splitHostPort(ref string) (host, port string, ok bool) {
	if strings.HasPrefix(ref, "[") {
		end := strings.LastIndex(ref, "]")
		if end < 0 {
			return ref, "", false
		}
		rest := ref[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return ref, "", false
		}
		return ref[1:end], rest[1:], validPort(rest[1:])
	}

	idx := strings.LastIndex(ref, ":")
	if idx < 0 || strings.Contains(ref[:idx], ":") {
		// No port, or a bare IPv6 literal with several colons.
		return ref, "", false
	}
	return ref[:idx], ref[idx+1:], validPort(ref[idx+1:])
}

func validPort(p string) bool {
	if p == "" {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n <= 65535
}

// joinHostPort re-forms a reference, bracketing an IPv6 literal.
func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// classify records a reference's identifying part for later assignment.
func classify(ref string, hosts, ips *[]string) {
	host, _, hasPort := splitHostPort(ref)
	if !hasPort {
		host = ref
	}
	if host == "" {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		*ips = append(*ips, host)
		return
	}
	*hosts = append(*hosts, host)
}
