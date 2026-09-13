package kafka

import (
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The recommendation for each layer a failure was evidenced at.
//
// The mapping is fixed by ADR 0034 section 18; only the wording is chosen here.
// A recommendation is tied to the evidenced failure layer and to nothing else,
// so a sweep that failed at TCP never suggests looking at certificates and one
// that failed at TLS never suggests looking at firewalls.
//
// A single generic recommendation is forbidden: "check networking" obscures the
// evidence the finding just proved. None of these is executable — svcdoctor
// suggests where to look and never what to run.
const (
	// Phase 13.1C REC-021. It used to open with "Check whether the advertised
	// hostname resolves from this vantage point", which asks the reader to redo
	// the measurement that produced this finding — svcdoctor resolved that name
	// from here and recorded the answer. What is left is the half svcdoctor
	// cannot answer: which names the broker's own listener configuration was
	// written to publish.
	recommendDNS = "Compare the name this broker publishes in advertised.listeners with the " +
		"names resolvable from this network position"
	recommendTCP = "Check routing, firewall rules and security group policy between this " +
		"vantage point and the advertised address and port"
	recommendTLS = "Check whether the broker certificate names the advertised host, and " +
		"whether its issuer is trusted at this vantage point"
)

// The rationales for the two layers whose advice is classified.
//
// **`recommendDNS` has none, and that is the point of the exemption.** Its
// action asks the operator to check whether the advertised hostname resolves
// from this vantage point — which is a measurement this run already took and
// recorded, since a DNS failure at the advertised endpoint is why the finding
// exists. Phase 13.1A recorded it as REC-021 and reserved the sentence for
// Phase 13.1C rather than classifying a clause that restates the report.
const (
	rationaleDNS = "svcdoctor asked this host's resolver for the advertised name and was " +
		"given no address it could use, so the name and this network position are the two " +
		"halves; which of them the advertisement was written for is held in the broker's own " +
		"listener configuration."

	rationaleTCP = "Name resolution succeeded for the advertised endpoint and the connection " +
		"did not, so what differs lies between this network position and that address; " +
		"routing, filtering and security-group policy are where that decision is made, and a " +
		"refused client observes no part of it."

	rationaleTLS = "The advertised host is the name a client would verify and the certificate " +
		"is what the broker presents for it, so the two are halves of one comparison; which " +
		"half is wrong is not something a failed handshake states."
)

// recommendations returns one recommendation per layer that positively evidenced
// a failure, in layer order.
//
// Only failing layers are mapped. A path that was never measured contributes no
// recommendation, because there is nothing yet to act on: what it needs is the
// hypothesis's discriminator, which asks for the measurement rather than for a
// change to the target.
func recommendations(
	failures []domain.Evidence, kind domain.FindingKind, confidence domain.Confidence,
) []domain.Recommendation {
	var layers []domain.Layer
	for _, f := range failures {
		if !slices.Contains(layers, f.Layer()) {
			layers = append(layers, f.Layer())
		}
	}
	slices.Sort(layers)

	out := make([]domain.Recommendation, 0, len(layers))
	for _, layer := range layers {
		action, safety, rationale, ok := recommendationFor(layer)
		if !ok {
			continue
		}
		// Every layer is classified since Phase 13.1C, so the list is uniform:
		// diagnosis.Recommend is the only construction path here and it refuses
		// an unclassified value rather than admitting one.
		out = append(out, diagnosis.Recommend(diagnosis.AdviceInput{
			Kind:   diagnosis.AdviceKindNextEvidence,
			Safety: safety,
			Action: action,
			// svcdoctor cannot take either: routing and filtering policy between
			// two positions, and what a broker is configured to present for a
			// name, are both outside what a refused client observes.
			SelfCollectable: false,
			Rationale:       rationale,
		}, kind, confidence)...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recommendationFor maps one evidenced failure layer to its advice.
//
// A layer outside the three the transport chain can fail at yields nothing
// rather than generic advice: inventing a suggestion for evidence this rule does
// not understand is exactly the expansion of policy the phase must not do.
func recommendationFor(
	layer domain.Layer,
) (action string, safety diagnosis.SafetyClass, rationale string, ok bool) {
	switch layer {
	case domain.LayerDNS:
		return recommendDNS, diagnosis.SafetyCompare, rationaleDNS, true
	case domain.LayerTCP:
		return recommendTCP, diagnosis.SafetyVerify, rationaleTCP, true
	case domain.LayerTLS:
		return recommendTLS, diagnosis.SafetyVerify, rationaleTLS, true
	default:
		return "", diagnosis.SafetyUnspecified, "", false
	}
}
