package kafka

import (
	"slices"

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
	recommendDNS = "Check whether the advertised hostname resolves from this vantage point, " +
		"and what the broker publishes in advertised.listeners"
	recommendTCP = "Check routing, firewall rules and security group policy between this " +
		"vantage point and the advertised address and port"
	recommendTLS = "Check whether the broker certificate names the advertised host, and " +
		"whether its issuer is trusted at this vantage point"
)

// recommendations returns one recommendation per layer that positively evidenced
// a failure, in layer order.
//
// Only failing layers are mapped. A path that was never measured contributes no
// recommendation, because there is nothing yet to act on: what it needs is the
// hypothesis's discriminator, which asks for the measurement rather than for a
// change to the target.
func recommendations(failures []domain.Evidence) []domain.Recommendation {
	var layers []domain.Layer
	for _, f := range failures {
		if !slices.Contains(layers, f.Layer()) {
			layers = append(layers, f.Layer())
		}
	}
	slices.Sort(layers)

	out := make([]domain.Recommendation, 0, len(layers))
	for _, layer := range layers {
		action, ok := recommendationFor(layer)
		if !ok {
			continue
		}
		recommendation, err := domain.NewRecommendation(action)
		if err != nil {
			// Unreachable: the three actions are constants and are non-empty,
			// trimmed and free of control characters. Pinned by
			// TestRecommendationTextIsValid.
			continue
		}
		out = append(out, recommendation)
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
func recommendationFor(layer domain.Layer) (string, bool) {
	switch layer {
	case domain.LayerDNS:
		return recommendDNS, true
	case domain.LayerTCP:
		return recommendTCP, true
	case domain.LayerTLS:
		return recommendTLS, true
	default:
		return "", false
	}
}
