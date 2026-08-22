package security

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// The first PostgreSQL end-to-end security check.
//
// Phase 4.1 added AttrKindIdentity and recorded a producer obligation: an
// adapter that records a role or a database as an ordinary string leaks it, and
// redaction cannot detect the mistake. Phase 4.3 is the first producer with such
// values, so this is where that obligation stops being theoretical.
//
// The evidence is built by driving the real adapter over a real socket. Nothing
// here hand-authors a node.
const (
	pgCanaryRole     = "payments_writer_secretish"
	pgCanaryDatabase = "payments_prod_customer42"
	pgCanaryHost     = "db-prod-canary.corp.internal"
	pgCanaryAddr     = "10.88.0.17"
	pgCanaryVantage  = "pg-runner-canary.local"

	// Planted in the server's ErrorResponse. None may reach a report, redacted
	// or not: the whitelist drops them at the wire boundary.
	pgCanaryMessage = "MESSAGE-CANARY-no-pg_hba-entry"
	pgCanaryDetail  = "DETAIL-CANARY-/var/lib/postgresql/pg_hba.conf"
	pgCanaryHint    = "HINT-CANARY-contact-dba@corp.internal"
)

// pgScriptedPeer answers a startup packet with an ErrorResponse full of prose.
func pgScriptedPeer(t *testing.T) netip.AddrPort {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() {
					time.Sleep(200 * time.Millisecond)
					_ = conn.Close()
				}()
				// Read the startup packet: length includes itself.
				var header [4]byte
				if _, readErr := readAll(conn, header[:]); readErr != nil {
					return
				}
				length := binary.BigEndian.Uint32(header[:])
				if length < 4 || length > 1<<16 {
					return
				}
				body := make([]byte, length-4)
				if _, readErr := readAll(conn, body); readErr != nil {
					return
				}
				_, _ = conn.Write(pgErrorResponse())
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func readAll(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// pgErrorResponse is shaped like a real pg_hba rejection, with every discarded
// field carrying a canary.
func pgErrorResponse() []byte {
	pairs := []string{
		"S", "FATAL",
		"V", "FATAL",
		"C", "28000",
		"M", pgCanaryMessage + ` user "` + pgCanaryRole + `" database "` + pgCanaryDatabase + `"`,
		"D", pgCanaryDetail,
		"H", pgCanaryHint,
		"F", "auth.c",
		"L", "530",
		"R", "ClientAuthentication",
	}
	var body []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		body = append(body, pairs[i][0])
		body = append(body, pairs[i+1]...)
		body = append(body, 0)
	}
	body = append(body, 0)

	out := []byte{'E'}
	// Bounded before the conversion: a fixture body is never near the limit,
	// and an unchecked int->uint32 is the shape of a real framing bug.
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // bounded above.
	return append(out, body...)
}

type pgResolver struct{ addr netip.Addr }

func (r pgResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{r.addr}, nil
}

type pgDialer struct{ target netip.AddrPort }

func (d pgDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// pgReport drives the real adapter and assembles a report from what it recorded.
func pgReport(t *testing.T) domain.Report {
	t.Helper()

	peer := pgScriptedPeer(t)
	builder := domain.NewGraphBuilder()

	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     pgCanaryHost,
		Port:     5432,
		Resolver: pgResolver{addr: netip.MustParseAddr(pgCanaryAddr)},
		Dialer:   pgDialer{target: peer},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	paths := result.Continuations()
	if len(paths) != 1 {
		t.Fatalf("got %d transport paths, want 1", len(paths))
	}

	session, err := postgres.Negotiate(context.Background(), builder, paths[0],
		postgres.Params{TLS: postgres.TLSDisabled})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if _, err := postgres.Startup(context.Background(), builder, session, postgres.StartupParams{
		User: pgCanaryRole, Database: pgCanaryDatabase,
	}); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	run, err := domain.NewRunMetadata("0.1.0", time.Now(), time.Second, "postgres")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(pgCanaryHost + ":5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(pgCanaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func encodePG(t *testing.T, r domain.Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(b)
}

// TestPostgresLocalReportCarriesTheIdentitiesAndNoServerProse is the control,
// and half the assertion.
//
// The role and database must be present locally — they are what the run is about
// — while the server's prose must be absent even here, because the whitelist
// drops it at the wire boundary rather than at the report boundary.
func TestPostgresLocalReportCarriesTheIdentitiesAndNoServerProse(t *testing.T) {
	encoded := encodePG(t, pgReport(t))

	for _, present := range []string{pgCanaryRole, pgCanaryDatabase, pgCanaryHost, pgCanaryAddr} {
		if !strings.Contains(encoded, present) {
			t.Errorf("the local report does not contain %q, so redacting it proves nothing", present)
		}
	}
	// The SQLSTATE survives: it is the machine-readable fact diagnosis will read.
	if !strings.Contains(encoded, "28000") {
		t.Error("the SQLSTATE did not reach evidence")
	}

	for _, absent := range []string{
		pgCanaryMessage, pgCanaryDetail, pgCanaryHint,
		"auth.c", "ClientAuthentication", "pg_hba.conf", "dba@corp.internal",
	} {
		if strings.Contains(encoded, absent) {
			t.Errorf("server prose %q reached a LOCAL_FULL report; the ErrorResponse "+
				"whitelist is not holding", absent)
		}
	}
}

// TestPostgresShareableReportLeaksNothing is the phase's security definition of
// done.
func TestPostgresShareableReportLeaksNothing(t *testing.T) {
	local := pgReport(t)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := encodePG(t, shareable)

	if got := shareable.Security().OutputMode(); got != domain.OutputModeShareableRedacted {
		t.Fatalf("output mode = %s, want SHAREABLE_REDACTED", got)
	}

	for _, canary := range []string{
		pgCanaryRole, pgCanaryDatabase, pgCanaryHost, pgCanaryAddr, pgCanaryVantage,
		pgCanaryMessage, pgCanaryDetail, pgCanaryHint,
	} {
		if strings.Contains(encoded, canary) {
			t.Errorf("%q survived into a report labelled SHAREABLE_REDACTED", canary)
		}
	}

	// Each category went to its own namespace.
	if !strings.Contains(encoded, "identity-") {
		t.Error("no identity pseudonym appears; the role and database were not redacted as identity")
	}
	if !strings.Contains(encoded, "ip-") {
		t.Error("no ip pseudonym appears")
	}
	if !strings.Contains(encoded, "evidence-") {
		t.Error("evidence identifiers were not remapped")
	}

	// The diagnostic facts survive, which is what makes the report worth sharing.
	for _, kept := range []string{"28000", "FATAL", "postgres.startup", "postgres.ssl_request", "L3", "L4"} {
		if !strings.Contains(encoded, kept) {
			t.Errorf("%q was destroyed by redaction", kept)
		}
	}

	counts := shareable.Security().Redactions()
	if counts.Identity != 2 {
		t.Errorf("identity count = %d, want 2 (a role and a database)", counts.Identity)
	}
}

// TestPostgresIdentitiesAreDeclaredNotInferred is the producer-obligation test
// Phase 4.1 asked for by name.
//
// It reads the kinds the adapter actually recorded. If a future edit changed
// AttrRole to a StringAttr, redaction would silently stop replacing it and the
// shareable report above would leak — so this asserts the cause rather than only
// the symptom.
func TestPostgresIdentitiesAreDeclaredNotInferred(t *testing.T) {
	report := pgReport(t)

	var checked int
	for _, node := range report.Graph().Nodes() {
		if node.Step() != postgres.StepStartup {
			continue
		}
		for _, key := range []domain.AttributeKey{postgres.AttrRole, postgres.AttrDatabase} {
			v, ok := node.Attribute(key)
			if !ok {
				t.Fatalf("attribute %s is missing from the startup node", key)
			}
			if v.Kind() != domain.AttrKindIdentity {
				t.Errorf("%s has kind %s, want identity: an ordinary string is not "+
					"recognized by redaction and would survive into a shareable report",
					key, v.Kind())
			}
			checked++
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d identity attributes, want 2", checked)
	}
}
