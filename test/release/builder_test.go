// Package release qualifies `scripts/build-release.sh`, the recipe that
// produces the five platform archives and `SHA256SUMS` ADR 0076 §2.3 makes
// required.
//
// # Why this is executed rather than reviewed
//
// The release archives are built once per release, on a tag, in a workflow
// nobody rehearses — the same conditions that produced v0.3.0 (a tag with no
// workflow), v0.3.1 (stopped by its own gate) and v0.3.2 (an image and no
// GitHub Release). RB-05 is that same class of defect one layer down: ADR 0076
// requires artifacts that no mechanism produced. A recipe that is only read is
// how it stays that way.
//
// # Why these tests build their own repository
//
// The builder refuses a dirty tree, and it must: an archive that corresponds to
// no commit is an archive nobody can trace. So it cannot be exercised against
// the repository a developer is working in — a single unsaved file would make
// every test here skip or fail for a reason that has nothing to do with the
// builder.
//
// Instead each run assembles a small Git repository from the *current* sources —
// `cmd/`, `internal/`, `go.mod`, `go.sum`, `LICENSE`, `README.md` and the
// builder itself — commits it, tags it, and builds that. The binary in the
// resulting archive is the real product binary, compiled from the same files
// `go build ./cmd/svcdoctor` would use.
//
// Two limitations, stated rather than papered over. The fixture's commit SHA is
// not the repository's, so this proves the recipe and not the provenance of any
// particular release. And `_test.go` files are omitted, because nothing here
// runs the product's tests — only builds it.
package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The version every fixture build is qualified at. It is the v0.4.0 candidate
// deliberately: this file is the executable half of the release qualification,
// and qualifying a version nobody intends to release would prove less.
const fixtureVersion = "v0.4.0"

// The exact artifact set. Named literally rather than generated from a platform
// list, so a builder that quietly stopped producing one of them has nothing here
// to agree with it.
//
// The naming follows the only binary release this project has published:
// v0.1.0's assets were `svcdoctor_0.1.0_<os>_<arch>.tar.gz` plus `SHA256SUMS`,
// and the v0.4.0 candidate gate recorded the same shape. The version segment
// carries no `v`; the Git tag does.
var wantArtifacts = []string{
	"svcdoctor_0.4.0_darwin_amd64.tar.gz",
	"svcdoctor_0.4.0_darwin_arm64.tar.gz",
	"svcdoctor_0.4.0_linux_amd64.tar.gz",
	"svcdoctor_0.4.0_linux_arm64.tar.gz",
	"svcdoctor_0.4.0_windows_amd64.zip",
}

// Everything an archive may contain. This is an allow-list and not a
// requirement list: a member outside it fails, whatever it is.
var wantMembers = []string{"LICENSE", "README.md", "svcdoctor"}

var wantWindowsMembers = []string{"LICENSE", "README.md", "svcdoctor.exe"}

// Paths that must never reach an archive. Every one of them exists in the
// repository the fixture is copied from, so a builder that archived a directory
// instead of naming its members would pick some of them up.
var forbiddenSubstrings = []string{
	".git", ".github", "CLAUDE.md", "AGENTS.md", "testdata", "test/",
	"examples", "docs/", "scripts/", "internal/", "cmd/", "go.mod", "go.sum",
	".DS_Store", ".pem", ".key", "secret", "credential", ".tmp",
}

// TestReleaseBuilder is REL-01 through REL-12.
//
// One fixture repository and one full build, shared by the subtests that read
// its output. Five cross-compilations are not free, and running them once per
// assertion would buy nothing: every REL-03..REL-12 claim is about the same set
// of artifacts.
func TestReleaseBuilder(t *testing.T) {
	repo := newFixtureRepo(t)

	t.Run("REL-01 a malformed version is rejected", func(t *testing.T) {
		for _, version := range []string{
			"0.4.0",       // no v
			"v0.4",        // not three components
			"v0.4.0.1",    // four
			"v0.4.0-rc.1", // a prerelease is not a release tag shape
			"main",        // a branch name is not a version
			"latest",      // a moving name is not a version
			"",            // nothing at all
			"v0.4.0; touch pwned",
		} {
			out := filepath.Join(t.TempDir(), "out")
			stdout, stderr, err := repo.build(t, version, out)
			if err == nil {
				t.Errorf("version %q was accepted:\n%s", version, stdout)
				continue
			}
			if version != "" && !strings.Contains(stderr, "not a vX.Y.Z release version") {
				t.Errorf("version %q was rejected for the wrong reason:\n%s", version, stderr)
			}
			if _, statErr := os.Stat(out); statErr == nil {
				t.Errorf("version %q created an output directory before being rejected", version)
			}
		}
		if _, err := os.Stat(filepath.Join(repo.dir, "pwned")); err == nil {
			t.Error("a version argument was interpreted by the shell")
		}
	})

	t.Run("REL-02 a dirty tree is rejected before compiling", func(t *testing.T) {
		readme := filepath.Join(repo.dir, "README.md")
		original, err := os.ReadFile(readme) //nolint:gosec // G304: a fixture path.
		if err != nil {
			t.Fatal(err)
		}
		//nolint:gosec // G703: a path under this test's own fixture directory.
		if err := os.WriteFile(readme, append(original, []byte("\nlocal edit\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
		defer func() {
			//nolint:gosec // G703: restoring the fixture file read above.
			if err := os.WriteFile(readme, original, 0o600); err != nil {
				t.Fatal(err)
			}
		}()

		out := filepath.Join(t.TempDir(), "out")
		stdout, stderr, err := repo.build(t, fixtureVersion, out)
		if err == nil {
			t.Fatalf("a dirty tree produced a release:\n%s", stdout)
		}
		if !strings.Contains(stderr, "working tree is dirty") {
			t.Errorf("the refusal does not name the dirty tree:\n%s", stderr)
		}
		if !strings.Contains(stderr, "README.md") {
			t.Errorf("the refusal does not say what is dirty:\n%s", stderr)
		}
		// Nothing was compiled: refusing after building five binaries would
		// still refuse, and would still have spent the source it refused over.
		if entries, statErr := os.ReadDir(out); statErr == nil && len(entries) > 0 {
			t.Errorf("a dirty tree produced %d output entries", len(entries))
		}
	})

	t.Run("an untagged HEAD is rejected in release mode", func(t *testing.T) {
		// The fixture is tagged v0.4.0. A different, equally well-formed version
		// is not on HEAD, and release mode must say so rather than build it.
		out := filepath.Join(t.TempDir(), "out")
		_, stderr, err := repo.build(t, "v9.9.9", out)
		if err == nil {
			t.Fatal("a version that is not a tag on HEAD produced a release")
		}
		if !strings.Contains(stderr, "does not carry the tag v9.9.9") {
			t.Errorf("the refusal does not name the missing tag:\n%s", stderr)
		}
	})

	t.Run("an untracked file in an ignored output directory is not source dirtiness", func(t *testing.T) {
		// The documented policy, and the reason the default output directory is
		// under the already-ignored `dist/`.
		stray := filepath.Join(repo.dir, "dist", "left-over.txt")
		if err := os.MkdirAll(filepath.Dir(stray), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stray, []byte("from an earlier run\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(filepath.Join(repo.dir, "dist")) }()

		status := repo.git(t, "status", "--porcelain", "--untracked-files=all")
		if strings.TrimSpace(status) != "" {
			t.Fatalf("the fixture does not ignore dist/, so this proves nothing: %q", status)
		}
		if _, _, err := repo.build(t, fixtureVersion, filepath.Join(repo.dir, "dist", "release")); err != nil {
			t.Errorf("an ignored output directory was treated as a dirty tree: %v", err)
		}
	})

	// The one full build. Everything below reads its output.
	out := filepath.Join(t.TempDir(), "release")
	stdout, stderr, err := repo.build(t, fixtureVersion, out)
	if err != nil {
		t.Fatalf("the release build failed: %v\n--- stdout ---\n%s\n--- stderr ---\n%s", err, stdout, stderr)
	}

	t.Run("REL-03 five archives are created", func(t *testing.T) {
		for _, name := range wantArtifacts {
			info, statErr := os.Stat(filepath.Join(out, name))
			if statErr != nil {
				t.Errorf("%s was not produced", name)
				continue
			}
			if info.Size() < 1<<20 {
				t.Errorf("%s is %d bytes, which is too small to contain a svcdoctor binary", name, info.Size())
			}
		}
	})

	t.Run("REL-04 SHA256SUMS is created", func(t *testing.T) {
		if _, statErr := os.Stat(filepath.Join(out, "SHA256SUMS")); statErr != nil {
			t.Fatal("SHA256SUMS was not produced")
		}
		if !strings.Contains(stdout, "Checksums verified with") {
			t.Error("the builder did not report verifying the checksums it wrote")
		}
	})

	t.Run("REL-05 every checksum is valid", func(t *testing.T) {
		lines := checksumLines(t, out)
		if len(lines) != len(wantArtifacts) {
			t.Fatalf("SHA256SUMS has %d lines, expected %d", len(lines), len(wantArtifacts))
		}
		for name, want := range lines {
			body, readErr := os.ReadFile(filepath.Join(out, name)) //nolint:gosec // G304: a path read from the file under test.
			if readErr != nil {
				t.Errorf("SHA256SUMS names %q, which does not exist", name)
				continue
			}
			sum := sha256.Sum256(body)
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("%s: SHA256SUMS says %s, the file hashes to %s", name, want, got)
			}
		}
		// Every archive is covered, and the checksum file does not cover itself.
		for _, name := range wantArtifacts {
			if _, ok := lines[name]; !ok {
				t.Errorf("SHA256SUMS does not cover %s", name)
			}
		}
		if _, ok := lines["SHA256SUMS"]; ok {
			t.Error("SHA256SUMS contains an entry for itself, which cannot be correct")
		}
	})

	t.Run("REL-06 SHA256SUMS carries no path", func(t *testing.T) {
		body := readFile(t, filepath.Join(out, "SHA256SUMS"))
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Errorf("malformed checksum line %q", line)
				continue
			}
			if strings.ContainsAny(fields[1], "/\\") || strings.HasPrefix(fields[1], ".") {
				t.Errorf("checksum line %q names a path rather than an artifact; it would "+
					"verify only on the machine that built it", line)
			}
		}
		if strings.Contains(body, out) || strings.Contains(body, repo.dir) {
			t.Error("SHA256SUMS leaks a local build path")
		}
	})

	t.Run("REL-07 archive contents are exactly the allow-list", func(t *testing.T) {
		for _, name := range wantArtifacts {
			want := wantMembers
			if strings.HasSuffix(name, ".zip") {
				want = wantWindowsMembers
			}
			got := archiveMembers(t, filepath.Join(out, name))
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("%s contains %v, expected %v", name, got, want)
			}
		}
	})

	t.Run("REL-08 no forbidden path is in any archive", func(t *testing.T) {
		for _, name := range wantArtifacts {
			for _, member := range archiveMembers(t, filepath.Join(out, name)) {
				if strings.Contains(member, "/") || strings.Contains(member, `\`) {
					t.Errorf("%s contains %q, which is a path rather than a flat member", name, member)
				}
				for _, forbidden := range forbiddenSubstrings {
					if strings.Contains(member, forbidden) {
						t.Errorf("%s contains %q, which matches the forbidden path %q", name, member, forbidden)
					}
				}
			}
		}
	})

	t.Run("REL-09 the native binary extracts and executes", func(t *testing.T) {
		archive, ok := nativeArchive()
		if !ok {
			t.Skipf("this platform (%s/%s) is not one of the five released ones, so no "+
				"artifact here can be executed", runtime.GOOS, runtime.GOARCH)
		}
		dir := t.TempDir()
		extractTarGz(t, filepath.Join(out, archive), dir)

		binary := filepath.Join(dir, "svcdoctor")
		info, statErr := os.Stat(binary)
		if statErr != nil {
			t.Fatalf("the extracted archive has no svcdoctor binary: %v", statErr)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("the extracted binary is not executable: mode %v", info.Mode().Perm())
		}
		if _, err := runIn(t.Context(), dir, binary, "--help"); err != nil {
			t.Fatalf("the extracted binary does not run: %v", err)
		}
	})

	t.Run("REL-10 the native binary reports the supplied version", func(t *testing.T) {
		archive, ok := nativeArchive()
		if !ok {
			t.Skipf("no native artifact on %s/%s", runtime.GOOS, runtime.GOARCH)
		}
		dir := t.TempDir()
		extractTarGz(t, filepath.Join(out, archive), dir)

		got, err := runIn(t.Context(), dir, filepath.Join(dir, "svcdoctor"), "--version")
		if err != nil {
			t.Fatalf("--version failed: %v", err)
		}
		if strings.TrimSpace(got) != fixtureVersion {
			t.Errorf("--version reports %q, expected %q.\n\n"+
				"The archive would then be named after one release and identify itself "+
				"as another, in every report it produced.", strings.TrimSpace(got), fixtureVersion)
		}
	})

	t.Run("REL-11 the foreign artifacts exist and carry the right executable", func(t *testing.T) {
		native, _ := nativeArchive()
		foreign := 0
		for _, name := range wantArtifacts {
			if name == native {
				continue
			}
			foreign++
			members := archiveMembers(t, filepath.Join(out, name))
			wantBinary := "svcdoctor"
			if strings.HasSuffix(name, ".zip") {
				wantBinary = "svcdoctor.exe"
			}
			if !contains(members, wantBinary) {
				t.Errorf("%s does not contain %s", name, wantBinary)
			}
			// A Windows archive carrying a Unix binary name, or the reverse,
			// would extract to something the platform cannot run.
			if strings.HasSuffix(name, ".tar.gz") && contains(members, "svcdoctor.exe") {
				t.Errorf("%s contains a Windows executable", name)
			}
			if strings.HasSuffix(name, ".zip") && contains(members, "svcdoctor") {
				t.Errorf("%s contains a Unix executable", name)
			}
		}
		if foreign < len(wantArtifacts)-1 {
			t.Errorf("only %d foreign artifacts were checked", foreign)
		}
	})

	t.Run("REL-12 the output directory holds nothing else", func(t *testing.T) {
		entries, readErr := os.ReadDir(out)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var got []string
		for _, e := range entries {
			if e.IsDir() {
				t.Errorf("%s is a directory; the output holds artifacts only", e.Name())
			}
			got = append(got, e.Name())
		}
		sort.Strings(got)
		want := append([]string{"SHA256SUMS"}, wantArtifacts...)
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("the output directory contains %v, expected %v", got, want)
		}
	})

	t.Run("a non-empty output directory is refused", func(t *testing.T) {
		// The same directory, a second time: it now holds a release, and mixing
		// two releases' artifacts is how a SHA256SUMS ends up describing files
		// nobody built together.
		_, stderr, err := repo.build(t, fixtureVersion, out)
		if err == nil {
			t.Fatal("a second build into a populated directory was allowed")
		}
		if !strings.Contains(stderr, "not empty") {
			t.Errorf("the refusal does not say why:\n%s", stderr)
		}
	})

	t.Run("the builder publishes nothing", func(t *testing.T) {
		// Belt and braces around the property that matters most: this recipe is
		// invoked by a workflow holding `contents: write`.
		script := readFile(t, filepath.Join(repo.dir, "scripts", "build-release.sh"))
		// Precise needles. `git tag --points-at` is how the builder *reads* the
		// release identity, and a pattern crude enough to catch that would have
		// to be deleted the first time it fired — taking the guard with it.
		for _, forbidden := range []string{
			"git push", "git tag -a", "git tag -f", "git tag \"", "gh release",
			"docker push", "cosign", "curl ", "wget ",
		} {
			if strings.Contains(script, forbidden) {
				t.Errorf("the release builder contains %q; it builds and checksums, and "+
					"publication belongs to the workflow", forbidden)
			}
		}
		if repo.git(t, "tag", "--list") != fixtureVersion+"\n" {
			t.Error("the builder changed the fixture's tags")
		}
		if strings.TrimSpace(repo.git(t, "status", "--porcelain", "--untracked-files=all")) != "" {
			t.Error("the builder left the source tree dirty")
		}
	})
}

// TestTheChecksumToolIsDetectedRatherThanAssumed is REL-05's portability half.
//
// The builder runs on a developer's macOS, which has `shasum` and no
// `sha256sum`, and on an ubuntu-latest runner, which has both. A recipe that
// assumed either would produce no checksum file on the other, and the failure
// would surface once, during a release.
//
// Both available implementations are exercised by hiding the other one.
func TestTheChecksumToolIsDetectedRatherThanAssumed(t *testing.T) {
	repo := newFixtureRepo(t)

	tools := map[string]string{}
	for _, tool := range []string{"sha256sum", "shasum"} {
		if path, err := exec.LookPath(tool); err == nil {
			tools[tool] = path
		}
	}
	if len(tools) == 0 {
		t.Fatal("neither sha256sum nor shasum is on PATH; the builder cannot run here at all")
	}

	for hidden := range tools {
		if len(tools) == 1 {
			t.Logf("only %v is available here; the other implementation is not exercised on this machine", keys(tools))
			break
		}
		t.Run("without "+hidden, func(t *testing.T) {
			// A PATH containing symlinks to everything except the hidden tool.
			shim := t.TempDir()
			for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if e.Name() == hidden {
						continue
					}
					_ = os.Symlink(filepath.Join(dir, e.Name()), filepath.Join(shim, e.Name()))
				}
			}
			if _, err := exec.LookPath(hidden); err == nil {
				// Confirm the shim actually hides it, or this proves nothing.
				if _, err := os.Stat(filepath.Join(shim, hidden)); err == nil {
					t.Fatalf("the shim still exposes %s", hidden)
				}
			}

			out := filepath.Join(t.TempDir(), "out")
			stdout, stderr, err := repo.buildWithEnv(t, []string{"PATH=" + shim}, fixtureVersion, out)
			if err != nil {
				t.Fatalf("the builder failed without %s: %v\n%s\n%s", hidden, err, stdout, stderr)
			}
			if lines := checksumLines(t, out); len(lines) != len(wantArtifacts) {
				t.Errorf("without %s the builder wrote %d checksum lines, expected %d",
					hidden, len(lines), len(wantArtifacts))
			}
		})
	}
}

// --- the fixture repository -------------------------------------------------

type fixtureRepo struct{ dir string }

// newFixtureRepo assembles a committed, tagged Git repository from the current
// sources. See the package comment for why.
func newFixtureRepo(t *testing.T) *fixtureRepo {
	t.Helper()

	for _, tool := range []string{"git", "go", "tar", "zip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required to qualify the release builder and is not on PATH.\n\n"+
				"This is not skipped: a release runs on a machine that has all four, and a "+
				"silently skipped release gate is how RB-05 stayed open.", tool)
		}
	}

	root := repoRoot(t)
	dir := t.TempDir()
	r := &fixtureRepo{dir: dir}

	copyFile(t, root, dir, "go.mod")
	copyFile(t, root, dir, "go.sum")
	copyFile(t, root, dir, "LICENSE")
	copyFile(t, root, dir, "README.md")
	copyFile(t, root, dir, "scripts/build-release.sh")
	// dist/ must be ignored here exactly as it is in the repository, because the
	// default output directory lives under it.
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("dist/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	copySources(t, root, dir, "cmd")
	copySources(t, root, dir, "internal")

	r.git(t, "init", "--quiet")
	r.git(t, "add", "-A")
	r.git(t, "-c", "user.email=release-qualification@svcdoctor.invalid",
		"-c", "user.name=release qualification",
		"commit", "--quiet", "-m", "release builder qualification fixture")
	r.git(t, "-c", "user.email=release-qualification@svcdoctor.invalid",
		"-c", "user.name=release qualification",
		"tag", "-a", fixtureVersion, "-m", "svcdoctor "+fixtureVersion)

	if status := r.git(t, "status", "--porcelain", "--untracked-files=all"); strings.TrimSpace(status) != "" {
		t.Fatalf("the fixture repository is not clean: %q", status)
	}
	return r
}

func (r *fixtureRepo) git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = r.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (r *fixtureRepo) build(t *testing.T, version, outDir string) (stdout, stderr string, err error) {
	t.Helper()
	return r.buildWithEnv(t, nil, version, outDir)
}

// buildWithEnv runs the builder. `extraEnv` entries override the inherited
// environment, which is otherwise passed through so the Go build cache and
// module cache are the ones the rest of the suite already warmed.
func (r *fixtureRepo) buildWithEnv(t *testing.T, extraEnv []string, version, outDir string) (string, string, error) {
	t.Helper()

	args := []string{"./scripts/build-release.sh"}
	if version != "" {
		args = append(args, version)
	}
	args = append(args, outDir)

	cmd := exec.CommandContext(t.Context(), "bash", args...) //nolint:gosec // G204: fixed script, test-supplied version.
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), extraEnv...)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// --- helpers ----------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func copyFile(t *testing.T, srcRoot, dstRoot, rel string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(srcRoot, rel)) //nolint:gosec // G304: a repository-relative path.
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dstRoot, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: a repository-relative path into the test's own temporary directory.
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// copySources copies the buildable Go sources of a tree: no `_test.go`, no
// `testdata`. Nothing here runs the product's own tests, and the fixture is
// smaller and faster for leaving them out.
func copySources(t *testing.T, srcRoot, dstRoot, rel string) {
	t.Helper()
	base := filepath.Join(srcRoot, rel)
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		child, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		copyFile(t, srcRoot, dstRoot, child)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // G304: a test-controlled path.
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// checksumLines parses SHA256SUMS into artifact name -> hex digest.
func checksumLines(t *testing.T, dir string) map[string]string {
	t.Helper()
	lines := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(dir, "SHA256SUMS"))), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed checksum line %q", line)
		}
		name := strings.TrimPrefix(fields[1], "*") // the binary-mode marker
		if _, duplicate := lines[name]; duplicate {
			t.Errorf("SHA256SUMS names %s twice", name)
		}
		lines[name] = fields[0]
	}
	return lines
}

// archiveMembers lists an archive's members, sorted. It reads tar.gz and zip
// with the standard library rather than shelling out to `tar` and `unzip` — the
// builder's own output must be readable by something other than the tools that
// wrote it, and `unzip` is one dependency fewer.
func archiveMembers(t *testing.T, path string) []string {
	t.Helper()
	if strings.HasSuffix(path, ".zip") {
		r, err := zip.OpenReader(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		defer func() { _ = r.Close() }()
		var names []string
		for _, f := range r.File {
			names = append(names, f.Name)
		}
		sort.Strings(names)
		return names
	}

	f, err := os.Open(path) //nolint:gosec // G304: a test-controlled path.
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	defer func() { _ = gz.Close() }()

	var names []string
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		names = append(names, header.Name)
	}
	sort.Strings(names)
	return names
}

func extractTarGz(t *testing.T, path, dir string) {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: a test-controlled path.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(header.Name, "/") || strings.Contains(header.Name, "..") {
			t.Fatalf("%s contains a path member %q", path, header.Name)
		}
		target := filepath.Join(dir, filepath.Base(header.Name)) //nolint:gosec // G305: base name of a checked member.
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.FileInfo().Mode().Perm())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(out, tr, header.Size); err != nil && !errors.Is(err, io.EOF) {
			_ = out.Close()
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func runIn(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: a path produced by the builder under test.
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %v: %w\n%s", name, args, err, out)
	}
	return string(out), nil
}

// nativeArchive reports the artifact this machine can execute, if any.
func nativeArchive() (string, bool) {
	want := fmt.Sprintf("svcdoctor_%s_%s_%s.tar.gz",
		strings.TrimPrefix(fixtureVersion, "v"), runtime.GOOS, runtime.GOARCH)
	return want, contains(wantArtifacts, want)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
