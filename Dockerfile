# syntax=docker/dockerfile:1

# Build on the native platform and cross-compile, so multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY gateway/go.mod gateway/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
# otelc injects the OpenTelemetry SDK and instrumentation at compile time.
# Build it for the build platform; `go tool otelc` would build it for the target.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /usr/local/bin/otelc go.opentelemetry.io/otelc/tool/cmd/otelc
COPY gateway/ ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    otelc go build -buildvcs=false -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/sekisho .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sekisho /usr/local/bin/sekisho
# The examples double as the default configuration; mount your own over /etc/sekisho.
COPY --chown=nonroot:nonroot gateway/examples/ /etc/sekisho/
WORKDIR /etc/sekisho
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sekisho"]
CMD ["-config", "/etc/sekisho/config.json"]
