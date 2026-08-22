package kafka

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// These tests pin the one property the Phase 3.6 vocabulary move had to have:
// nothing observable changed.
//
// StepMetadata, StepBrokerAdvertised and AttrBrokerNodeID moved to
// internal/service/kafka so that internal/diagnosis/kafka can name them without
// importing this package, which depguard denies (ADR 0034 section 19). They are
// re-exported here, so the move is a change of definition site and of nothing
// else — but "and of nothing else" is exactly the kind of claim that needs a
// test rather than a comment. A rename would break every consumer matching on
// the string; docs/FINDINGS.md section 2 says a code is the stable part, and the
// same reasoning governs a step name in a serialized report.

// TestMovedVocabularyKeepsItsWireValues pins the literal strings.
func TestMovedVocabularyKeepsItsWireValues(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
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

// TestReExportsAreTheLeafDefinitions proves the adapter did not keep a second
// copy that could drift from the one diagnosis reads.
func TestReExportsAreTheLeafDefinitions(t *testing.T) {
	if StepMetadata != servicekafka.StepMetadata {
		t.Error("StepMetadata is not the leaf definition")
	}
	if StepBrokerAdvertised != servicekafka.StepBrokerAdvertised {
		t.Error("StepBrokerAdvertised is not the leaf definition")
	}
	if AttrBrokerNodeID != servicekafka.AttrBrokerNodeID {
		t.Error("AttrBrokerNodeID is not the leaf definition")
	}
}

// TestSerializedTopologyEvidenceIsUnchanged is the end-to-end half: real
// Metadata evidence, marshalled the way the report will marshal it, still
// carries the same step names and the same attribute key.
func TestSerializedTopologyEvidenceIsUnchanged(t *testing.T) {
	target := authenticatedTarget(t, withControllerID(2))
	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	steps := map[string]int{}
	sawNodeID := false
	for _, evidence := range graph.Nodes() {
		encoded, err := json.Marshal(evidence)
		if err != nil {
			t.Fatalf("marshalling %s: %v", evidence.ID(), err)
		}
		text := string(encoded)

		switch evidence.Step() {
		case StepMetadata:
			steps["kafka.metadata"]++
			if !strings.Contains(text, `"step":"kafka.metadata"`) {
				t.Errorf("metadata node does not serialize its step: %s", text)
			}
		case StepBrokerAdvertised:
			steps["kafka.broker_advertised"]++
			if !strings.Contains(text, `"step":"kafka.broker_advertised"`) {
				t.Errorf("advertisement does not serialize its step: %s", text)
			}
			if strings.Contains(text, `"kafka.broker.node_id"`) {
				sawNodeID = true
			}
		}
	}

	if steps["kafka.metadata"] != 1 {
		t.Errorf("kafka.metadata nodes = %d, want 1", steps["kafka.metadata"])
	}
	if steps["kafka.broker_advertised"] == 0 {
		t.Error("no kafka.broker_advertised node was produced")
	}
	if !sawNodeID {
		t.Error("no advertisement serialized the kafka.broker.node_id attribute")
	}
}

// TestTheAdapterKeptItsOwnKeys pins the other half of ADR 0034 section 19: only
// the three constants a rule needs moved, and the rest stayed where they are
// produced.
//
// In particular the advertised host and port stayed, because they are already on
// the advertisement's subject and a second copy would create two sources for one
// fact.
func TestTheAdapterKeptItsOwnKeys(t *testing.T) {
	stayed := map[string]domain.AttributeKey{
		"kafka.metadata.controller_id":               AttrMetadataControllerID,
		"kafka.metadata.broker_count":                AttrMetadataBrokerCount,
		"kafka.metadata.advertised_entry_count":      AttrMetadataAdvertisedEntryCount,
		"kafka.metadata.unrepresentable_entry_count": AttrMetadataUnrepresentableCount,
		"kafka.broker.advertised_host":               AttrBrokerAdvertisedHost,
		"kafka.broker.advertised_port":               AttrBrokerAdvertisedPort,
	}
	for want, got := range stayed {
		if string(got) != want {
			t.Errorf("attribute key = %q, want %q", got, want)
		}
	}
}
