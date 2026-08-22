// Package transport is where generic transport diagnosis will live.
//
// It is deliberately empty of production code. ADR 0042 gave a future rule the
// structure it needs — a requested-target anchor, and a sweep that declares its
// cause — and authorized no finding whatsoever. What such a rule may claim, what
// code it carries, and its severity, confidence and vantage semantics are Phase
// 4.9a's decisions and have not been made.
//
// This file exists to keep that gap honest. An empty directory drifts silently;
// a test that fails the moment a rule appears does not.
//
// The companion half of this guard — that no generic transport finding code is
// declared anywhere in the module — lives in internal/vocabulary, because
// depguard denies this package the file-system access a repository-wide scan
// needs. That denial is correct and worth keeping: diagnosis reads a frozen
// graph, and a diagnosis package that could read files would eventually read one.
package transport

import (
	gobuild "go/build"
	"testing"
)

// TestNoGenericTransportRuleExistsYet pins the boundary of Phase 4.9a-pre.
//
// The anchor makes a generic rule *possible*. It does not make one *decided*,
// and shipping one on the strength of "the structure is there now" would be the
// invented diagnostic policy ADR 0017 exists to prevent — in the one layer whose
// entire purpose is not to invent.
//
// Delete this test in Phase 4.9a, when a record says what the rule may claim.
func TestNoGenericTransportRuleExistsYet(t *testing.T) {
	pkg, err := gobuild.ImportDir(".", 0)
	if err != nil {
		// No buildable Go source in the directory is exactly the state this
		// test wants, and go/build reports it as an error.
		return
	}

	for _, name := range pkg.GoFiles {
		t.Errorf("%s exists; generic transport diagnosis is Phase 4.9a and no record "+
			"yet says what it may claim (ADR 0017, ADR 0042 status)", name)
	}
}
