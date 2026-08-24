# Running svcdoctor in Kubernetes

svcdoctor runs, reports and exits. It is a **Job**, not a Deployment — there is
no server to keep alive, no port to serve and nothing to keep warm. See
[ADR 0062](../../docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md).

## Why run it in the cluster at all

Because reachability is a property of *where you are standing*. svcdoctor
already reports every connectivity finding as vantage-relative; running it
inside the target network is what makes that vantage the one you care about.

The clearest case is Kafka. A bootstrap endpoint can be perfectly reachable
while the brokers it advertises are not — an advertised-listener
misconfiguration that a client outside the cluster cannot see and a client
inside it hits immediately. svcdoctor measures the bootstrap endpoint *and*
every advertised endpoint from the Pod, and reports each one separately:

```
outcome    Kafka metadata obtained
topology   0 of 3 advertised broker endpoints reached
```

Credentials never follow that discovery. The bootstrap endpoint you named is
the only endpoint that is ever offered one; advertised brokers get
credential-free DNS, TCP and TLS and nothing else (ADR 0050).

## The two examples

| File | What it does |
|---|---|
| [`job-postgres.yaml`](job-postgres.yaml) | One PostgreSQL diagnosis: DNS, TCP, `SSLRequest`, TLS, `Startup`, SCRAM authentication, session |
| [`job-kafka.yaml`](job-kafka.yaml) | One Kafka diagnosis: bootstrap journey plus the advertised-broker sweep |

Both are complete and runnable once you substitute the image reference, the
host and the Secret. Neither contains a real credential.

## Secrets

svcdoctor reads a credential from a **file** or from **stdin**. There is no
environment-variable secret source, and this is deliberate: environment
variables leak into pod specs, `kubectl describe` output, support bundles and CI
logs far more readily than a mounted file does. svcdoctor's production code
calls `os.Getenv` exactly zero times, so this is a structural property rather
than a convention.

Mount the Secret read-only and point `--password-file` at it:

```yaml
volumeMounts:
  - name: credential
    mountPath: /run/secrets
    readOnly: true
volumes:
  - name: credential
    secret:
      secretName: svcdoctor-postgres
      defaultMode: 0400
```

`defaultMode: 0400` plus `fsGroup: 65532` makes the file readable by the
runtime user and nobody else. If the file is not readable, svcdoctor fails the
invocation cleanly — exit 2, `permission denied`, no fallback to another
source, no attempt to change the mode, and the secret is never echoed.

Treat the Secret as ephemeral: create it, run the Job, delete both. svcdoctor
does not delete it, because svcdoctor has no Kubernetes API access at all
(see below).

## Trust

With no `--tls-ca-file`, svcdoctor uses the image's system trust store. With
one, the supplied file **replaces** the system roots — it does not extend them —
so only its issuers are accepted. Mount a private CA from a ConfigMap or Secret
and name it:

```yaml
- --tls-ca-file=/run/certs/ca.crt
```

A malformed, missing or unreadable CA file fails the invocation with exit 2
before any connection is attempted.

## No Kubernetes API access

svcdoctor never calls the Kubernetes API. It needs no ServiceAccount
permissions, no Role and no RoleBinding, so both examples set:

```yaml
automountServiceAccountToken: false
```

If a platform creates these Jobs, *that platform* needs the API permissions.
svcdoctor stays a bounded diagnostic worker.

## Timeout and the Job deadline

Set `activeDeadlineSeconds` **above** svcdoctor's own `--timeout`, so svcdoctor
reaches its budget first and exits with a report. If Kubernetes kills the Pod
first you get no report at all — only a terminated container.

```
--timeout 30s   →   activeDeadlineSeconds: 60
```

## Reading the result

Use `--output json` and capture stdout:

```sh
kubectl logs job/svcdoctor-postgres
```

Exit codes are the contract (`docs/SCOPE.md`); `0` does **not** mean healthy.
A run with no credential configured exits 0 with a WARN finding and no session.
For a release gate, read the JSON as well as the exit code.

Logs carry real hostnames and addresses. `--shareable` pseudonymizes them, but
it also removes identity a machine consumer may need to correlate — so it is
the right default for sharing a report with someone else, not for every
pipeline.

## Image references

**These examples name an image that does not exist yet.** No svcdoctor image has been
published to GHCR or anywhere else. Until the first release, build one locally:

```sh
scripts/build-image.sh --dev --platform linux/arm64   # tags svcdoctor:sha-<commit>
```

and substitute that reference.

After publication, the canonical name is `ghcr.io/hakanaltindag/svcdoctor`, and production
deployments should pin the **digest** rather than the tag:

```yaml
image: ghcr.io/hakanaltindag/svcdoctor@sha256:<digest of the release>
```

A semver tag is immutable by policy; a digest is immutable by construction, and does not
depend on that policy being honoured. `latest` is never appropriate here. See
[ADR 0062](../../docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md) §13.

## What is not here

No Helm chart, no operator, no controller and no CRD. svcdoctor is a CLI that a
platform invokes; it does not become an agent.
