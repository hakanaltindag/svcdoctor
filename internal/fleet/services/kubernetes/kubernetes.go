// Package kubernetes owns the Kubernetes shape of a multi-target configuration.
//
// It decodes and validates. It opens no socket, resolves no name and reads no
// credential.
//
// It is the service that proves internal/fleet/config.EndpointDeriver: a
// Kubernetes target names **no host and no port**, because its API server is
// derived from the kubeconfig context the target already names, or is the API
// Service's own name in-cluster. Writing either would be an inert field, and
// ADR 0060's discipline is that an inert input is refused rather than accepted.
//
// # It is the one service configuration that reads a file while decoding
//
// The kubeconfig is this target's authority, and three things are only knowable
// from it: whether the target is usable, which API server it resolves to, and
// whether it carries a construct svcdoctor refuses. Deferring that to execution
// would turn a kubeconfig containing an `exec` credential plugin into one
// target's execution failure at exit 4, instead of a configuration error at exit
// 2 with nothing dialled — which is the defect Phase 9.1C found in the credential
// path and fixed for exactly this reason. See config.Factory.
package kubernetes

import (
	"context"
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Kind is the value of a target's `type` field.
const Kind = "kubernetes"

// DefaultPort is the port an https API server URL defaults to.
//
// It satisfies the registry's non-zero requirement without inventing anything:
// 443 is the scheme's own default, and it is what a kubeconfig `server:` with no
// port means. It is never used to reach anything — the port actually dialled is
// the one the derived endpoint carries — which is why a Kubernetes target may
// name no port at all.
const DefaultPort = 443

// Config is a Kubernetes target's own configuration.
//
// **Five fields, and there is deliberately no sixth.** There is no selector, no
// Pod name, no workload, no label filter, no wildcard, no regexp, no list of
// Services and no all-namespaces mode: each of those is a field that does not
// exist rather than a value that is rejected, which is the difference between a
// contract and a validation rule.
type Config struct {
	// Kubeconfig is an explicit path to exactly one kubeconfig file.
	//
	// KUBECONFIG is not consulted, ~/.kube/config is not a fallback, and a merge
	// list is not supported: a merge list makes one configuration file mean
	// different things on different machines, which is the failure a fleet
	// configuration exists to remove.
	Kubeconfig string `yaml:"kubeconfig"`

	// Context is the kubeconfig context to use. Required with Kubeconfig.
	//
	// The file's `current-context` is never used. A defaulted context makes one
	// configuration read a different cluster on a different machine, and its
	// failure mode — reading the wrong cluster and reporting "not found" — is
	// indistinguishable from a real finding.
	Context string `yaml:"context"`

	// InCluster selects the pod's own projected ServiceAccount identity.
	//
	// Explicit only, mutually exclusive with Kubeconfig, and never a fallback: a
	// mounted ServiceAccount token must never cause svcdoctor to acquire an
	// identity nobody asked for.
	InCluster bool `yaml:"in_cluster"`

	// Namespace is required and explicit. Never taken from the context, never
	// defaulted to "default".
	Namespace string `yaml:"namespace"`

	// ServiceName is the one Service this target is about. Required.
	ServiceName string `yaml:"service_name"`

	// apiHost and apiPort are the API server Decode resolved.
	//
	// Unexported, so nothing can write them from a configuration file and no
	// operator can override the endpoint the authority itself declares. They are
	// what DerivedEndpoint answers with, and they are what the credential is
	// bound to.
	apiHost string
	apiPort uint16
}

// Kind reports the service this configuration belongs to.
func (c Config) Kind() string { return Kind }

// target projects the configuration onto the adapter's target type.
func (c Config) target() app.KubernetesTarget {
	return app.KubernetesTarget{
		Kubeconfig:  c.Kubeconfig,
		Context:     c.Context,
		InCluster:   c.InCluster,
		Namespace:   c.Namespace,
		ServiceName: c.ServiceName,
	}
}

// Factory registers Kubernetes with the generic configuration core and with the
// runner registry.
//
// One type implementing three interfaces — config.Factory, config.EndpointDeriver
// and run.Runner — so a service is registered once. The zero Factory is usable
// for configuration alone; Run is the only method that reads Env.
type Factory struct {
	// Env carries the vantage and the version. Required for Run.
	//
	// The resolver and dialer it also carries are unused here, and that is a fact
	// about this service rather than an omission: every Kubernetes read goes
	// through the API client, which owns its own transport, so there is no
	// svcdoctor probe seam to inject. It is accepted whole because the type is
	// the generic one every service receives.
	Env services.Environment
}

// Kind returns the registration key.
func (Factory) Kind() string { return Kind }

// DefaultPort returns the port an https API server URL defaults to.
func (Factory) DefaultPort() uint16 { return DefaultPort }

// Decode turns the `config:` subtree into a Config and validates the target.
//
// It reads the kubeconfig, because that file is this target's authority and
// every refusal it carries must be a configuration error rather than a run-time
// one. See the package comment.
func (Factory) Decode(node *config.ServiceNode, common config.Common) (config.ServiceConfig, error) {
	var cfg Config
	if err := node.Decode(&cfg); err != nil {
		return nil, err
	}

	if err := checkInertTLS(common.TLS); err != nil {
		return nil, err
	}
	if err := checkInertIdentity(common.Credentials); err != nil {
		return nil, err
	}

	// The credential reference is a **bearer token** for the API server. Whether
	// one was declared is all the ambiguity check needs, and it is knowable here
	// where no secret has been resolved: a target that names a token *and* a
	// kubeconfig user carrying one declares two identities, and svcdoctor refuses
	// the ambiguity rather than choosing.
	host, port, err := app.InspectKubernetesTarget(
		cfg.target(), !common.Credentials.Password.IsZero())
	if err != nil {
		return nil, config.InvalidField("config", err.Error())
	}
	cfg.apiHost = host
	cfg.apiPort = port
	return cfg, nil
}

// DerivedEndpoint returns the API server Decode resolved.
//
// It computes nothing and reads nothing: Decode already answered, and asking the
// file twice would let two reads of one path disagree.
func (Factory) DerivedEndpoint(serviceConfig config.ServiceConfig) (string, uint16, error) {
	cfg, ok := serviceConfig.(Config)
	if !ok {
		return "", 0, fmt.Errorf(
			"%w: the Kubernetes endpoint was asked of %T", config.ErrConfig, serviceConfig)
	}
	return cfg.apiHost, cfg.apiPort, nil
}

// checkInertTLS refuses a `tls:` block a Kubernetes target cannot use.
//
// The API server's trust material comes from the kubeconfig's own
// `certificate-authority`, or from the projected ServiceAccount CA in-cluster.
// A `tls.ca_file` beside that would be a second, contradictory answer to one
// question; a `tls.server_name` would override an identity the kubeconfig
// already states; and `tls.insecure` asks svcdoctor to disable the verification
// it performs before presenting a credential, which it refuses in every mode.
//
// `tls.mode: disable` is refused for the same reason `insecure-skip-tls-verify`
// is: svcdoctor presents a credential to the API server, and it will not do that
// over a channel it cannot verify.
//
// Refused rather than ignored, because an operator who wrote one of these
// believes they configured — or deliberately relaxed — something.
func checkInertTLS(tls config.TLS) error {
	switch {
	case !tls.Enabled():
		return config.InvalidField("tls.mode",
			"a Kubernetes target always speaks TLS to the API server, and svcdoctor will not "+
				"present a credential over a channel it cannot verify")
	case tls.CAFile != "":
		return config.InvalidField("tls.ca_file",
			"a Kubernetes target takes its trust material from the kubeconfig's "+
				"certificate-authority, or from the projected ServiceAccount CA in-cluster")
	case tls.ServerName != "":
		return config.InvalidField("tls.server_name",
			"a Kubernetes target verifies the identity the kubeconfig cluster states")
	case tls.Insecure:
		return config.InvalidField("tls.insecure",
			"svcdoctor does not disable API server verification; it presents a credential "+
				"there, and it will not recommend or silently accept an unverified channel")
	}
	return nil
}

// checkInertIdentity refuses a username a Kubernetes target cannot use.
//
// None of the four supported modes carries one: a bearer token and a client
// certificate each *are* the identity, and the API server decides who they name.
// Basic authentication, which is the only mode that would use a username, is
// refused outright.
func checkInertIdentity(credentials config.Credentials) error {
	if credentials.Username != "" {
		return config.InvalidField("credentials.username",
			"a Kubernetes credential carries no username: a bearer token and a client "+
				"certificate each are the identity, and the API server decides who they name")
	}
	return nil
}

// Run turns a validated target into app.KubernetesParams and calls the existing
// composition root.
//
// The credential arrives already bound to the API server's endpoint, because the
// endpoint the scheduler bound it to is the one Decode derived. **Nothing here
// rebinds it**; the composition root checks the binding rather than trusting it,
// and a mismatch is a refusal.
func (f Factory) Run(
	ctx context.Context, target config.Target, credential security.Credential,
) (run.Outcome, error) {
	cfg, ok := target.Config.(Config)
	if !ok {
		return run.Outcome{}, fmt.Errorf(
			"kubernetes runner received %T, which is not a Kubernetes configuration",
			target.Config)
	}

	result, err := app.DiagnoseKubernetes(ctx, app.KubernetesParams{
		Target:     cfg.target(),
		Credential: credential,
		Vantage:    f.Env.Vantage,
		Version:    f.Env.Version,
	})
	if err != nil {
		return run.Outcome{}, err
	}
	return run.Outcome{Report: result.Report(), Incomplete: result.Incomplete()}, nil
}
