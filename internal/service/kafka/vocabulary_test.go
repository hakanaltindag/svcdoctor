package kafka

import "testing"

// TestVocabularyValuesAreTheContract pins the strings themselves.
//
// They reach the canonical report, and automation matches on them. A constant
// here is renamed only with the same deliberation docs/FINDINGS.md section 2
// requires of a finding code.
func TestVocabularyValuesAreTheContract(t *testing.T) {
	cases := []struct{ name, got, want string }{
		{"StepMetadata", string(StepMetadata), "kafka.metadata"},
		{"StepBrokerAdvertised", string(StepBrokerAdvertised), "kafka.broker_advertised"},
		{"AttrBrokerNodeID", string(AttrBrokerNodeID), "kafka.broker.node_id"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestVocabularyIsWellFormed checks the values against the grammar the domain
// enforces, so an invalid constant fails here rather than at the first evidence
// node that uses it.
func TestVocabularyIsWellFormed(t *testing.T) {
	if !StepMetadata.Valid() {
		t.Errorf("%q is not a valid step", StepMetadata)
	}
	if !StepBrokerAdvertised.Valid() {
		t.Errorf("%q is not a valid step", StepBrokerAdvertised)
	}
	if !AttrBrokerNodeID.Valid() {
		t.Errorf("%q is not a valid attribute key", AttrBrokerNodeID)
	}
}
