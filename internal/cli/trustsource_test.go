package cli

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// The trust-source contract, held at the one place both services load it.
//
// # Why this needs its own file
//
// `trustSource` is shared by `diagnose postgres` and `diagnose kafka`, so one
// test covers the policy for the whole product. Until Phase 6.6 it was tested
// only for what it *refuses* — a malformed file, a missing file, contents never
// reaching an error. Nothing tested what the pool it returns actually contains.
//
// Mutation found the gap. Replacing `x509.NewCertPool()` with
// `x509.SystemCertPool()` — so a supplied CA is *added to* the system store
// rather than replacing it — passed the entire repository suite. That is the
// single most consequential clause of ADR 0058 §2, and it silently widens trust:
// an operator who names the wrong CA still gets a passing handshake against any
// publicly-issued certificate, and concludes their private PKI is correct.

// TestASuppliedCAReplacesTheSystemStore is ADR 0058 §2, stated as an equality.
//
// The returned pool must equal a pool built from the supplied PEM **and nothing
// else**. Comparing against the expected pool rather than counting certificates
// is what makes the assertion total: a pool that gained the system roots is
// unequal whatever its size turns out to be on the machine running the test.
func TestASuppliedCAReplacesTheSystemStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	writeCA(t, path)

	got, err := trustSource(path)
	if err != nil {
		t.Fatalf("trustSource: %v", err)
	}
	if got == nil {
		t.Fatal("trustSource returned no pool for a valid CA file")
	}

	pem, err := os.ReadFile(path) //nolint:gosec // G304: a path this test wrote.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := x509.NewCertPool()
	if !want.AppendCertsFromPEM(pem) {
		t.Fatal("the fixture CA does not parse")
	}

	if !got.Equal(want) {
		t.Error("the trust pool is not exactly the supplied CA.\n\n" +
			"ADR 0058 section 2: a supplied --tls-ca-file is the complete trust " +
			"source and system roots are not consulted. A pool that also holds the " +
			"system store cannot express \"only this issuer is acceptable here\", and " +
			"lets a wrong CA file still produce a passing handshake.")
	}

	// And the system store really is a different, larger thing, so the equality
	// above is discriminating rather than accidentally true on this machine.
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system trust store on this platform: %v", err)
	}
	if got.Equal(system) {
		t.Error("the supplied-CA pool equals the system store; the test proves nothing here")
	}
}

// TestNoCAFileMeansTheSystemStore pins the other half of the policy.
//
// A nil pool is how `crypto/tls` is told to use the host's roots, and it is what
// an operator who passed no flag asked for. A test that only pinned replacement
// would be satisfied by an implementation that returned an empty pool here,
// which would trust nothing at all.
func TestNoCAFileMeansTheSystemStore(t *testing.T) {
	got, err := trustSource("")
	if err != nil {
		t.Fatalf("trustSource(\"\"): %v", err)
	}
	if got != nil {
		t.Error("trustSource returned a pool for an unset --tls-ca-file; " +
			"nil is what selects the system trust store")
	}
}

// TestAnUnusableCAFileNeverFallsBack is the fail-closed half of ADR 0058 §2.
//
// Every shape here is a file the operator explicitly named and svcdoctor cannot
// use. Each must be an invocation error. **Returning `(nil, nil)` would select
// the system trust store**, which is the widest possible trust, chosen silently,
// in response to the operator asking for the narrowest.
func TestAnUnusableCAFileNeverFallsBack(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}

	dangling := filepath.Join(dir, "dangling.pem")
	if err := os.Symlink(filepath.Join(dir, "absent-target.pem"), dangling); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"empty file", write("empty.pem", "")},
		{"no PEM at all", write("garbage.pem", "not a certificate\n")},
		{"a PEM block that is not a certificate", write("key.pem",
			"-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n")},
		{"a certificate block that does not parse", write("trunc.pem",
			"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n")},
		{"missing file", filepath.Join(dir, "absent.pem")},
		{"a directory", dir},
		{"dangling symlink", dangling},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := trustSource(tt.path)
			if err == nil {
				t.Fatalf("accepted an unusable trust source (pool=%v)", pool != nil)
			}
			if pool != nil {
				t.Error("a refused trust source still returned a pool")
			}
		})
	}
}

// TestAPartlyUsableCAFileKeepsWhatParsed records the one accepting case, so the
// behaviour is a decision rather than an accident.
//
// `AppendCertsFromPEM` reports success when it added at least one certificate,
// so a file holding a valid CA followed by unrelated bytes yields a pool with
// that CA in it. That is Go's contract and svcdoctor does not second-guess it:
// the operator's certificate was found and used, and nothing wider was added.
func TestAPartlyUsableCAFileKeepsWhatParsed(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "ca.pem")
	writeCA(t, clean)

	pem, err := os.ReadFile(clean) //nolint:gosec // G304: a path this test wrote.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	mixed := filepath.Join(dir, "mixed.pem")
	contents := append(pem, []byte("\ntrailing garbage\n")...)
	//nolint:gosec // G703: both the path and the contents are this test's own,
	// built from t.TempDir() and a certificate it generated a moment ago.
	if err := os.WriteFile(mixed, contents, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := trustSource(mixed)
	if err != nil {
		t.Fatalf("trustSource: %v", err)
	}
	want := x509.NewCertPool()
	want.AppendCertsFromPEM(pem)
	if !got.Equal(want) {
		t.Error("a file with one valid CA and trailing garbage did not yield exactly that CA")
	}
}
