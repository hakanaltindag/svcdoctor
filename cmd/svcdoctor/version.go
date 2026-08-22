package main

import (
	"runtime/debug"
	"strings"
)

// version is svcdoctor's own version when a release build injects one.
//
// A plain package variable so a release build can set it with
// `-ldflags "-X main.version=..."`, and a development default so a build from
// source is honest about what it is rather than claiming a release.
//
// It is the *first* of two sources; resolveVersion combines it with the module
// version Go stamps into every binary. Both are fixed at build time, so the
// value remains deterministic — no semver library, and no git invocation at
// runtime, because the result lands in the report.
var version = "dev"

// devVersion is what a build that cannot prove it came from a released module
// reports. It is deliberately not a version number.
const devVersion = "dev"

// develVersion is what Go stamps as the main module's version when it has no
// version to state at all, which happens with `-buildvcs=false`.
const develVersion = "(devel)"

// synthesizedPath is what Go reports as the main module's path when a build was
// given a file list rather than a package. It can surface as a version-shaped
// placeholder, and it is not a version.
const synthesizedPath = "command-line-arguments"

// dirtySuffix is what Go appends to the stamped module version when the working
// tree had uncommitted changes at build time.
//
// A binary carrying it was built from something no commit contains, so it
// corresponds to no release however its base version reads. That makes it a
// development build, and `v0.1.0+dirty` is treated exactly like a pseudo-version
// rather than as the release it resembles.
const dirtySuffix = "+dirty"

// resolvedVersion reports the version this binary should claim.
//
// It is the one authority: cmd passes the result to internal/cli, which prints
// it for --version *and* records it in the report's run metadata. A binary that
// told the operator one version and the report another would make every shared
// report ambiguous about what produced it.
func resolvedVersion() string {
	moduleVersion := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		moduleVersion = info.Main.Version
	}
	return resolveVersion(version, moduleVersion)
}

// resolveVersion picks the version to report from the two build-time sources.
//
// It is pure so that every case below is a table test rather than a build
// experiment. debug.ReadBuildInfo cannot be injected, so the I/O is the two
// lines above and the decision is all here.
//
//  1. an injected version   a release artifact was built with -ldflags
//  2. a released module     `go install <module>/cmd/svcdoctor@v0.1.0`
//  3. "dev"                 anything else
//
// # Why the module version is not simply used when it is non-empty
//
// The obvious test — *accept anything that is not `(devel)` or empty* — is
// wrong, and measurably so. Go stamps the main module's version from VCS, so an
// ordinary `go build` in a git checkout does **not** produce `(devel)`: it
// produces a **pseudo-version** such as
//
//	v0.0.0-20260822214307-26e7baec140b
//
// A resolver using that test would make every development build announce a
// version number that was never released, in --version and in every report. The
// `(devel)` case is real but narrow — it appears with `-buildvcs=false` — and it
// is not the case that matters.
//
// Nor can the VCS build settings discriminate. `go install <module>@<commit>`
// resolves through the module proxy, which carries no repository, so that build
// has **no** VCS settings and still reports a pseudo-version. Presence of VCS
// stamping therefore separates neither case from a real tag.
//
// What does separate them is the shape of the version itself: a pseudo-version
// is Go's synthesized stand-in for "no tag names this commit", and a released
// module version is not one. So the predicate is exactly that, plus the `+dirty`
// marker Go adds when the tree had uncommitted changes — the ordinary state of a
// working checkout, and the reason this was measured rather than reasoned about.
func resolveVersion(injected, moduleVersion string) string {
	// An injected version wins outright, including over a module version. A
	// release artifact states what release it is; nothing may second-guess it.
	if injected != "" && injected != devVersion {
		return injected
	}

	switch {
	case moduleVersion == "",
		moduleVersion == develVersion,
		moduleVersion == synthesizedPath,
		strings.HasSuffix(moduleVersion, dirtySuffix),
		isPseudoVersion(moduleVersion):
		return devVersion
	}
	return moduleVersion
}

// isPseudoVersion reports whether v is one of Go's synthesized pseudo-versions.
//
// The three forms differ in their prefix and agree in their suffix:
//
//	v0.0.0-20060102150405-abcdef123456          no base tag
//	v1.2.3-pre.0.20060102150405-abcdef123456    base is a prerelease
//	v1.2.4-0.20060102150405-abcdef123456        base is a release
//
// All of them end in a 14-digit UTC timestamp and a 12-character lowercase hex
// revision, so that suffix is the whole test. Only the suffix is checked: the
// prefixes are the part that varies, and matching them would be a
// reimplementation of golang.org/x/mod — a dependency this repository does not
// have and does not need for a yes-or-no question.
//
// # The timestamp's separator is not always a hyphen
//
// The revision is always preceded by a hyphen, but the timestamp is preceded by
// a **dot** in the two forms that build on a base tag, because there the
// timestamp is a component of the prerelease string rather than a field of its
// own. Splitting on hyphens alone recognizes the first form and misses the other
// two, which is exactly the shape a development build of a tagged repository
// produces — so both separators are accepted.
//
// A released version never has this shape. `v0.1.0`, `v1.2.3-rc.1` and
// `v2.0.0+incompatible` all fail the check and are reported as themselves.
func isPseudoVersion(v string) bool {
	lastDash := strings.LastIndexByte(v, '-')
	if lastDash < 0 {
		return false
	}
	revision := v[lastDash+1:]

	rest := v[:lastDash]
	separator := max(
		strings.LastIndexByte(rest, '-'),
		strings.LastIndexByte(rest, '.'),
	)
	if separator < 0 {
		return false
	}
	timestamp := rest[separator+1:]

	return isDigits(timestamp, 14) && isLowerHex(revision, 12)
}

// isDigits reports whether s is exactly n ASCII digits.
func isDigits(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isLowerHex reports whether s is exactly n lowercase hexadecimal characters.
//
// Lowercase only, because that is what Go writes. Accepting uppercase would
// widen the predicate past the thing it is testing for.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
