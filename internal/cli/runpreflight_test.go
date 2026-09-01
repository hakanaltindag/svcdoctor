package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 9.2B, UX-B03: a configuration defect never reaches execution.
//
// # What Phase 9.2A measured
//
// The same operator mistake, on the two entry points:
//
//	leaf   --host fe80::1%en0        exit 2, "invalid invocation"
//	fleet  host: fe80::1%en0         exit 4, EXECUTION_FAILED, class INTERNAL
//
//	leaf   --tls-ca-file /nope.pem   exit 2, "cannot be read: no such file"
//	fleet  tls: { ca_file: /nope }   exit 4, EXECUTION_FAILED, class INTERNAL
//
// internal/domain/executionstate.go states the invariant both violated, in its
// own words: "configuration errors never reach execution at all — ADR 0074 §9
// requires a whole configuration to validate before any target is dialled, so
// the only failures reachable here are svcdoctor-local ones during a run."
//
// Three consequences, and only the first is cosmetic. A typo was reported as
// svcdoctor's invariant failing, so an operator files a bug against the tool. A
// CI policy that retries on 4 — "incomplete, the measurement did not finish" —
// retries forever on a value that can never work. And the message carried a
// local path into a report the operator may then share, which is UX-B01.
//
// These drive the real command. They assert the code, the streams, the absence
// of a report, and — the part that cannot be inferred from any of those — that
// no socket was opened.

// TestUX08APreflightDefectExitsTwoAndDialsNothing is the whole contract in one
// test, per defect category.
//
// # Why the listener is the assertion and not the timing
//
// "It exited too fast to have dialled" is not a proof, and on a loaded machine
// it is not even reliable. So the configuration's *valid* target points at a
// real listener this test owns, and the test asserts the accept count is zero.
// A preflight that let execution start would connect to it, because the target
// is reachable by construction.
func TestUX08APreflightDefectExitsTwoAndDialsNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		broken  func(t *testing.T, dir string) string
		wantErr string
	}{
		{
			name: "zoned IPv6 host",
			broken: func(t *testing.T, _ string) string {
				t.Helper()
				return brokenTarget("    host: \"fe80::1%en0\"\n" +
					"    tls:\n      mode: disable\n")
			},
			wantErr: "carries an IPv6 zone identifier",
		},
		{
			name: "trust source that does not exist",
			broken: func(t *testing.T, dir string) string {
				t.Helper()
				return brokenTarget("    host: db.example.invalid\n" +
					"    tls:\n      mode: require\n      ca_file: " +
					filepath.Join(dir, "absent-ca.pem") + "\n")
			},
			wantErr: "tls.ca_file: cannot be read: no such file",
		},
		{
			name: "trust source that is unreadable",
			broken: func(t *testing.T, dir string) string {
				t.Helper()
				if os.Geteuid() == 0 {
					t.Skip("running as root; an unreadable file is still readable")
				}
				path := filepath.Join(dir, "locked-ca.pem")
				writeCACertificate(t, path)
				if err := os.Chmod(path, 0o000); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
				return brokenTarget("    host: db.example.invalid\n" +
					"    tls:\n      mode: require\n      ca_file: " + path + "\n")
			},
			wantErr: "tls.ca_file: cannot be read: permission denied",
		},
		{
			name: "trust source holding no certificate",
			broken: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "empty-ca.pem")
				if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				return brokenTarget("    host: db.example.invalid\n" +
					"    tls:\n      mode: require\n      ca_file: " + path + "\n")
			},
			wantErr: "tls.ca_file: contains no PEM certificate",
		},
		{
			name: "credential reference naming an unset variable",
			broken: func(t *testing.T, _ string) string {
				t.Helper()
				return "  - id: broken\n    type: postgres\n" +
					"    host: db.example.invalid\n" +
					"    tls:\n      mode: disable\n" +
					"    credentials:\n      username: app\n" +
					"      password:\n        env: SVCDOCTOR_UX08_NEVER_SET\n"
			},
			wantErr: "credential",
		},
		{
			name: "credential reference naming an absent file",
			broken: func(t *testing.T, dir string) string {
				t.Helper()
				return "  - id: broken\n    type: postgres\n" +
					"    host: db.example.invalid\n" +
					"    tls:\n      mode: disable\n" +
					"    credentials:\n      username: app\n" +
					"      password:\n        file: " +
					filepath.Join(dir, "absent-password") + "\n"
			},
			wantErr: "credential",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			listener, accepted := countingListener(t)

			// Built once. Each case owns its whole target block, because a case
			// that supplies its own `tls:` and a caller that appends one produce
			// a duplicate mapping key — a different error, in a test about this
			// one.
			path := filepath.Join(dir, "services.yaml")
			writeConfigFile(t, path, "version: 1\nrun:\n  concurrency: 1\ntargets:\n"+
				reachableTarget("healthy", listener.Addr().String())+tc.broken(t, dir))

			got := runCLI(t, context.Background(), "run", "--config", path)

			if got.code != ExitUsage {
				t.Errorf("exit code %d, want %d.\n\n"+
					"UX-B03 / ADR 0077 §2.5: a defect in a target's own configuration is a "+
					"configuration error. Exit 4 says svcdoctor's execution did not finish, "+
					"which tells a pipeline to retry something that can never succeed.\n"+
					"stdout:\n%s\nstderr:\n%s", got.code, ExitUsage, got.stdout, got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout carried %d bytes.\n\n"+
					"ADR 0074 §9: a configuration error means zero targets dialled and no "+
					"report. A partial aggregate here would be a document about a run that "+
					"never happened.\nstdout:\n%s", len(got.stdout), got.stdout)
			}
			if !strings.Contains(got.stderr, tc.wantErr) {
				t.Errorf("stderr does not mention %q.\nstderr: %s", tc.wantErr, got.stderr)
			}
			if !strings.Contains(got.stderr, `"broken"`) {
				t.Errorf("stderr does not name the offending target.\nstderr: %s", got.stderr)
			}
			if n := accepted.Load(); n != 0 {
				t.Errorf("%d connection(s) reached the listener.\n\n"+
					"Preflight opens no socket. The healthy target in this configuration is "+
					"reachable by construction, so any accept here means execution started "+
					"before the configuration had been validated.", n)
			}
		})
	}
}

// TestUX08TheZeroNetworkGuardCanFail is the non-vacuity proof for the accept
// count.
//
// A listener nobody ever reaches, a counter nobody increments and a
// countingListener with a silent bug all look identical to the assertions above:
// zero. This drives a configuration with **no** defect and requires the count to
// rise, so the instrument is known to work before its zero readings mean
// anything.
func TestUX08TheZeroNetworkGuardCanFail(t *testing.T) {
	dir := t.TempDir()
	listener, accepted := countingListener(t)

	path := filepath.Join(dir, "services.yaml")
	writeConfigFile(t, path, "version: 1\nrun:\n  concurrency: 1\ntargets:\n"+
		reachableTarget("healthy", listener.Addr().String()))

	// The listener accepts and closes, so the journey fails after TCP. The code
	// is not what is under test here — the accept count is.
	_ = runCLI(t, context.Background(), "run", "--config", path)

	if accepted.Load() == 0 {
		t.Fatal("a valid configuration dialled nothing.\n\n" +
			"Every zero-accept assertion in TestUX08APreflightDefectExitsTwoAndDialsNothing " +
			"would then pass vacuously, including on a build where preflight does not run " +
			"at all.")
	}
}

// TestUX08PreflightAndTheLeafCommandsAgree pins the consistency the audit found
// missing.
//
// The point is not that both refuse. It is that both refuse *the same way*: the
// same code, no report, and an explanation naming the input the operator wrote.
// Divergence here is how UX-B03 existed at all — each surface was individually
// defensible and nothing compared them.
func TestUX08PreflightAndTheLeafCommandsAgree(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent-ca.pem")

	for _, tc := range []struct {
		name   string
		leaf   []string
		fleet  string
		reason string
	}{
		{
			name:   "zoned IPv6 host",
			leaf:   []string{"diagnose", "postgres", "--host", "fe80::1%en0", "--user", "app", "--tls", "disable"},
			fleet:  "    host: \"fe80::1%en0\"\n    tls:\n      mode: disable\n",
			reason: "carries an IPv6 zone identifier",
		},
		{
			name: "absent trust source",
			leaf: []string{"diagnose", "postgres", "--host", "db.example.invalid",
				"--user", "app", "--tls-ca-file", absent},
			fleet:  "    host: db.example.invalid\n    tls:\n      mode: require\n      ca_file: " + absent + "\n",
			reason: "no such file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := runCLI(t, context.Background(), tc.leaf...)

			path := filepath.Join(t.TempDir(), "services.yaml")
			writeConfigFile(t, path, "version: 1\ntargets:\n  - id: t\n    type: postgres\n"+
				tc.fleet+"    credentials:\n      username: app\n")
			fleet := runCLI(t, context.Background(), "run", "--config", path)

			if leaf.code != ExitUsage || fleet.code != ExitUsage {
				t.Errorf("leaf exited %d and the fleet path exited %d; both must be %d.\n"+
					"leaf stderr:  %s\nfleet stderr: %s",
					leaf.code, fleet.code, ExitUsage, leaf.stderr, fleet.stderr)
			}
			if leaf.stdout != "" || fleet.stdout != "" {
				t.Error("a refused invocation wrote to stdout on one of the two surfaces")
			}
			for surface, stderr := range map[string]string{
				"leaf": leaf.stderr, "fleet": fleet.stderr,
			} {
				if !strings.Contains(stderr, tc.reason) {
					t.Errorf("the %s explanation does not mention %q.\n%s",
						surface, tc.reason, stderr)
				}
			}
		})
	}
}

// TestUX08PreflightIsDistinctFromAPostPreflightFailure keeps the Phase 9.1
// distinction the fix must not flatten.
//
// # The two are not the same failure and must not get the same answer
//
//	known at preflight   the file was already absent, or the host was already
//	                     unusable. Nothing about the run has happened. It is a
//	                     configuration error: exit 2, no report, nothing dialled.
//
//	after preflight      the material was there, was proved loadable, and then
//	                     went away while the run was in flight. That is a local
//	                     *execution* failure: the run produced an aggregate, that
//	                     target is EXECUTION_FAILED, and the run is incomplete —
//	                     exit 4.
//
// Classifying the second as a configuration error would be the mirror of the
// defect being fixed: it would claim nothing was dialled when other targets were
// measured, and it would discard their reports.
//
// The window is forced rather than raced: the first target's own budget holds the
// run open long enough for the file to be removed, with concurrency 1 so the
// second target has provably not started.
func TestUX08PreflightIsDistinctFromAPostPreflightFailure(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "corp-root-ca.pem")
	writeCACertificate(t, ca)

	path := filepath.Join(dir, "services.yaml")
	writeConfigFile(t, path, "version: 1\n"+
		"run:\n  concurrency: 1\n  timeout: 30s\n"+
		"targets:\n"+
		"  - id: slow-first\n    type: postgres\n"+
		// A documentation-range address that is routed nowhere, so the connect
		// blocks for its whole step budget. `.invalid` was tried first and is
		// useless here: it fails at DNS in milliseconds, which closes the window
		// before it opens.
		"    host: 192.0.2.1\n"+
		"    timeout: 20s\n    step_timeout: 4s\n"+
		"    tls:\n      mode: disable\n"+
		"    credentials:\n      username: app\n"+
		"  - id: vanishing-trust\n    type: postgres\n"+
		"    host: second.example.invalid\n"+
		"    tls:\n      mode: require\n      ca_file: "+ca+"\n"+
		"    credentials:\n      username: app\n")

	// Preflight must pass: the file exists right now.
	done := make(chan blackBox, 1)
	go func() { done <- runCLI(t, context.Background(), "run", "--config", path, "--output", "json") }()

	time.Sleep(250 * time.Millisecond)
	if err := os.Remove(ca); err != nil {
		t.Fatalf("removing the trust source mid-run: %v", err)
	}
	got := <-done

	if got.code == ExitUsage {
		t.Fatalf("a trust source that vanished mid-run was reported as a configuration "+
			"error.\n\nPreflight proved it loadable, so its disappearance is a local "+
			"execution failure and the run still produced an aggregate for the other "+
			"target. Collapsing the two would discard real measurements.\nstderr: %s",
			got.stderr)
	}
	if got.code != ExitIncomplete {
		t.Errorf("exit code %d, want %d for a post-preflight local failure",
			got.code, ExitIncomplete)
	}
	if got.stdout == "" {
		t.Fatal("no aggregate was written; a post-preflight failure keeps the reports " +
			"of every target that did run")
	}
	if !strings.Contains(got.stdout, "EXECUTION_FAILED") {
		t.Errorf("the aggregate holds no EXECUTION_FAILED result.\nstdout:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "vanishing-trust") {
		t.Errorf("the aggregate does not name the target that failed.\nstdout:\n%s", got.stdout)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeConfigFile writes a configuration at an exact path.
//
// Distinct from secret_test.go's writeFile, which mints its own temporary name:
// these cases need the path in the file's own `ca_file` value, so the path has
// to be chosen before the contents are built.
func writeConfigFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// countingListener accepts and immediately closes, counting every connection.
//
// Immediately closing is deliberate: this exists to observe that a connection
// was attempted, not to speak any protocol. A target reaching it gets a TCP
// success and then a failed journey, which is a perfectly truthful report and
// not what any test here asserts on.
func countingListener(t *testing.T) (net.Listener, *atomic.Int64) {
	t.Helper()

	var config net.ListenConfig
	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return listener, &accepted
}

// reachableTarget writes a plaintext PostgreSQL target aimed at addr.
func reachableTarget(id, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic("reachableTarget: " + err.Error())
	}
	return "  - id: " + id + "\n    type: postgres\n" +
		"    host: " + host + "\n    port: " + port + "\n" +
		"    timeout: 10s\n    step_timeout: 3s\n" +
		"    tls:\n      mode: disable\n" +
		"    credentials:\n      username: app\n"
}

// writeCACertificate writes a self-signed certificate that trustsource accepts.
//
// Generated rather than committed: the material is throwaway, it is never
// presented to anything, and a checked-in certificate expires and fails a test
// years later for a reason that has nothing to do with the test.
func writeCACertificate(t *testing.T, path string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
}

// brokenTarget wraps a target's own fields in the identifier every case shares.
//
// The identifier is fixed at "broken" because the assertions look for it in
// stderr: an error that refuses a target without naming it is an error an
// operator cannot act on in a file with forty entries.
func brokenTarget(fields string) string {
	return "  - id: broken\n    type: postgres\n" + fields +
		"    credentials:\n      username: app\n"
}
