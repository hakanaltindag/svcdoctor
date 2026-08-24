# svcdoctor OCI image — see docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md
#
# Two stages. The builder cross-compiles a static binary; the final stage is a
# distroless base that contributes exactly three things svcdoctor needs and
# nothing that can execute.
#
# Build:
#   docker buildx build --build-arg VERSION=v0.3.0 -t svcdoctor:v0.3.0 .
#
# The image is a CLI, not a service. It has no ENTRYPOINT shell, no HEALTHCHECK
# and no EXPOSE, because svcdoctor runs, reports and exits.

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
#
# Pinned to a digest, not a floating tag. `golang:1.26` would silently change
# the compiler that produced a released artifact.
#
# --platform=$BUILDPLATFORM runs the toolchain natively and cross-compiles to
# $TARGETARCH. Building linux/amd64 under arm64 emulation instead would be
# slower and would compile with a QEMU-translated toolchain, which is a worse
# thing to trust than Go's own cross-compiler.
FROM --platform=$BUILDPLATFORM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS builder

WORKDIR /src

# Dependency layer first, so an edit to a .go file does not re-download the
# module graph. go.sum pins the one dependency; `go mod download` verifies it.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Only the two source trees. `.dockerignore` is deny-by-default, so this is not
# `COPY . .` wearing a disguise — docs/, test/, scripts/ and .git are not in the
# build context at all.
COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG TARGETOS
ARG TARGETARCH

# VERSION is the single version authority, identical to the one README.md
# documents for release binaries: -ldflags "-X main.version=...". There is no
# SVCDOCTOR_VERSION environment variable and no runtime version lookup, so
# --version, the report's run metadata and the OCI version label cannot drift
# apart. Left as "dev" the binary honestly reports a development build.
ARG VERSION=dev

# CGO_ENABLED=0 for a static binary with no libc dependency; -trimpath so no
# builder filesystem path is baked into it; -buildvcs=false because .git is
# deliberately outside the build context and the version comes from VERSION.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/svcdoctor \
      ./cmd/svcdoctor

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
#
# gcr.io/distroless/static-debian12:nonroot, pinned to the multi-platform index
# digest so each architecture resolves from one reviewed manifest list.
#
# It contributes exactly what a static Go network client needs:
#
#   /etc/ssl/certs/ca-certificates.crt   the system trust store. svcdoctor
#                                        passes RootCAs=nil when no
#                                        --tls-ca-file is given, and Go then
#                                        reads this file. A scratch image would
#                                        make that nil mean "trust nothing" —
#                                        a silent change to TLS trust semantics.
#   /etc/nsswitch.conf, /etc/passwd       Go's pure resolver consults nsswitch;
#                                        passwd carries the nonroot identity.
#   /etc/resolv.conf, /etc/hosts          placeholders the container runtime
#                                        replaces at start.
#
# It contains no executable of any kind: no shell, no package manager, no
# busybox. Verified by inventory, not assumed.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# OCI image metadata. These are labels — build metadata inside the image config.
# They are not provenance: SLSA/build provenance is an external attestation and
# is not what this block produces.
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="svcdoctor" \
      org.opencontainers.image.description="Diagnoses PostgreSQL and Kafka service connectivity from where it is run" \
      org.opencontainers.image.source="https://github.com/hakanaltindag/svcdoctor" \
      org.opencontainers.image.url="https://github.com/hakanaltindag/svcdoctor" \
      org.opencontainers.image.documentation="https://github.com/hakanaltindag/svcdoctor/blob/main/README.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/svcdoctor /svcdoctor

# Numeric UID:GID, not the name "nonroot". Kubernetes `runAsNonRoot: true`
# verifies the image's configured user before the container starts, and it can
# only do that when the value is numeric — a name would force it to resolve
# /etc/passwd, which it does not do, making the pod fail to start.
#
# 65532:65532 is the base image's established nonroot identity. Repeating it
# here is deliberate: it makes the runtime identity readable in this file rather
# than inherited invisibly from a base image digest.
USER 65532:65532

# `/` rather than the base image's /home/nonroot. svcdoctor never writes and
# never reads a relative path, so it needs a working directory that exists and
# nothing more. /home/nonroot is mode 0700 and owned by 65532, which would work
# — but depending on it would mean a run breaks if a securityContext changes the
# UID, for no benefit.
WORKDIR /

# The binary directly, with no shell. A wrapper script would need a shell in the
# final image, would sit between the container runtime and the process that
# handles SIGTERM, and would add quoting and injection surface around operator
# arguments. svcdoctor spawns no child processes, so there is nothing to reap
# and no init shim is needed either.
#
# No CMD: `docker run IMAGE` with no arguments prints usage and exits 2, and
# `docker run IMAGE diagnose postgres --host db` appends to the entrypoint.
ENTRYPOINT ["/svcdoctor"]
