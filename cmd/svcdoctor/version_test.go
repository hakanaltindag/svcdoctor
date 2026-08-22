package main

import "testing"

// TestResolveVersion pins the precedence contract: an injected version, then a
// released module version, then "dev".
//
// The pseudo-version cases are the ones that matter. They are not hypothetical:
// every `go build` and `go install ./cmd/svcdoctor` in a git checkout stamps one,
// so a resolver that accepted them would make development builds claim releases.
func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name      string
		injected  string
		moduleVer string
		want      string
	}{
		// 1. An injected version wins.
		{
			name:      "ldflags version is reported",
			injected:  "v0.1.0",
			moduleVer: "",
			want:      "v0.1.0",
		},
		{
			// The precedence that makes a release artifact authoritative: the
			// module version is real and is still not what the binary claims.
			name:      "ldflags overrides a released module version",
			injected:  "v0.1.0",
			moduleVer: "v0.0.9",
			want:      "v0.1.0",
		},
		{
			name:      "ldflags overrides a pseudo-version",
			injected:  "v0.1.0",
			moduleVer: "v0.0.0-20260822214307-26e7baec140b",
			want:      "v0.1.0",
		},

		// 2. A released module version, with no injection.
		{
			name:      "tagged module install is reported",
			injected:  "dev",
			moduleVer: "v0.1.0",
			want:      "v0.1.0",
		},
		{
			name:      "prerelease tag is reported as itself",
			injected:  "dev",
			moduleVer: "v1.2.3-rc.1",
			want:      "v1.2.3-rc.1",
		},
		{
			name:      "incompatible major is reported as itself",
			injected:  "dev",
			moduleVer: "v2.0.0+incompatible",
			want:      "v2.0.0+incompatible",
		},

		// 3. Everything else is "dev".
		{
			// The measured shape of an ordinary `go build` in this checkout.
			name:      "pseudo-version with no base tag stays dev",
			injected:  "dev",
			moduleVer: "v0.0.0-20260822214307-26e7baec140b",
			want:      "dev",
		},
		{
			name:      "pseudo-version above a release tag stays dev",
			injected:  "dev",
			moduleVer: "v1.2.4-0.20060102150405-abcdef123456",
			want:      "dev",
		},
		{
			name:      "pseudo-version above a prerelease tag stays dev",
			injected:  "dev",
			moduleVer: "v1.2.3-pre.0.20060102150405-abcdef123456",
			want:      "dev",
		},
		{
			// What `-buildvcs=false` stamps.
			name:      "devel stays dev",
			injected:  "dev",
			moduleVer: "(devel)",
			want:      "dev",
		},
		{
			// The ordinary state of a working checkout, and the measured output
			// of `go build` with any uncommitted change present.
			name:      "dirty pseudo-version stays dev",
			injected:  "dev",
			moduleVer: "v0.0.0-20260822214307-26e7baec140b+dirty",
			want:      "dev",
		},
		{
			// A dirty build at a tagged commit is not that release: it contains
			// changes no commit holds, so it must not claim the tag.
			name:      "dirty release tag stays dev",
			injected:  "dev",
			moduleVer: "v0.1.0+dirty",
			want:      "dev",
		},
		{
			name:      "placeholder module path stays dev",
			injected:  "dev",
			moduleVer: "command-line-arguments",
			want:      "dev",
		},
		{
			// debug.ReadBuildInfo reported nothing usable.
			name:      "empty build info stays dev",
			injected:  "dev",
			moduleVer: "",
			want:      "dev",
		},
		{
			// An injected empty string must not become the reported version.
			name:      "empty injection with no module version stays dev",
			injected:  "",
			moduleVer: "",
			want:      "dev",
		},
		{
			name:      "empty injection still accepts a released module version",
			injected:  "",
			moduleVer: "v0.1.0",
			want:      "v0.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.injected, tt.moduleVer); got != tt.want {
				t.Errorf("resolveVersion(%q, %q) = %q, want %q",
					tt.injected, tt.moduleVer, got, tt.want)
			}
		})
	}
}

// TestResolvedVersionNeverLeaksAPlaceholder guards the user-facing promise: the
// three strings that mean "Go had nothing to tell us" must never be printed or
// recorded in a report.
func TestResolvedVersionNeverLeaksAPlaceholder(t *testing.T) {
	forbidden := []string{"(devel)", "", "command-line-arguments"}

	for _, moduleVer := range []string{
		"", "(devel)", "command-line-arguments",
		"v0.0.0-20260822214307-26e7baec140b",
	} {
		got := resolveVersion("dev", moduleVer)
		for _, bad := range forbidden {
			if got == bad {
				t.Errorf("resolveVersion(\"dev\", %q) = %q, which must never reach a user",
					moduleVer, got)
			}
		}
	}
}

// TestResolvedVersionIsNeverEmpty pins the one property every caller depends on:
// domain.NewRunMetadata rejects an empty version, so a run built from this value
// would fail rather than report.
func TestResolvedVersionIsNeverEmpty(t *testing.T) {
	if got := resolvedVersion(); got == "" {
		t.Error("resolvedVersion() is empty; the report constructor rejects that")
	}
}

// TestIsPseudoVersion checks the predicate directly, including the near-misses
// that a loose suffix match would wrongly claim.
func TestIsPseudoVersion(t *testing.T) {
	pseudo := []string{
		"v0.0.0-20060102150405-abcdef123456",
		"v1.2.4-0.20060102150405-abcdef123456",
		"v1.2.3-pre.0.20060102150405-abcdef123456",
		"v0.0.0-20260822214307-26e7baec140b",
	}
	for _, v := range pseudo {
		if !isPseudoVersion(v) {
			t.Errorf("isPseudoVersion(%q) = false, want true", v)
		}
	}

	released := []string{
		"v0.1.0",
		"v1.2.3",
		"v1.2.3-rc.1",
		"v2.0.0+incompatible",
		"(devel)",
		"",
		"dev",
		// Near-misses: right shape, wrong widths or wrong alphabet.
		"v0.0.0-2006010215040-abcdef123456",   // 13-digit timestamp
		"v0.0.0-20060102150405-abcdef12345",   // 11-char revision
		"v0.0.0-20060102150405-ABCDEF123456",  // uppercase revision
		"v0.0.0-20060102150405-abcdefg123456", // non-hex revision
		"v0.0.0-notatimestamp-abcdef123456",   // non-numeric timestamp
	}
	for _, v := range released {
		if isPseudoVersion(v) {
			t.Errorf("isPseudoVersion(%q) = true, want false", v)
		}
	}
}
