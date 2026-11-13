<p align="center">
  <a href="https://sekisho.mvd.im">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/public/brand/wordmark-dark.svg">
      <img alt="Sekisho 関所 — OIDC policy gateway" src="docs/public/brand/wordmark-light.svg" width="460">
    </picture>
  </a>
</p>

<p align="center">
  <b>Every request passes the gate.</b><br>
  <a href="https://sekisho.mvd.im">Documentation</a> ·
  <a href="https://sekisho.mvd.im/quickstart">Quickstart</a> ·
  <a href="https://sekisho.mvd.im/configuration">Configuration</a>
</p>

---

Sekisho is an OIDC-aware policy gateway. It verifies inbound JWTs, requires every operation in a local OpenAPI 3 spec to be covered by composable [CEL](https://cel.dev) policies, and forwards allowed requests to a single upstream — using least-privilege backend credentials, or the caller's token only where a route opts in.

## Install

Download a binary for Linux, macOS or Windows from the [latest release](https://github.com/meesvandongen/sekisho/releases/latest), or run the container image:

```sh
docker run --rm -p 8080:8080 -v "$PWD/sekisho:/etc/sekisho:ro" ghcr.io/meesvandongen/sekisho
```

```sh
curl -fsSL https://github.com/meesvandongen/sekisho/releases/latest/download/sekisho_linux_amd64.tar.gz | tar -xz
./sekisho_linux_amd64/sekisho -config sekisho_linux_amd64/examples/config.json -explain
```

Both are built with compile-time OpenTelemetry. See [installation](https://sekisho.mvd.im/installation) for every platform and the [quickstart](https://sekisho.mvd.im/quickstart) for secrets and OpenTelemetry settings.

## Repository

| Path | Contents |
| --- | --- |
| [`gateway/`](./gateway) | The Go gateway, its tests and [example configuration](./gateway/examples). |
| [`Dockerfile`](./Dockerfile) | The container image published to `ghcr.io/meesvandongen/sekisho`. |
| [`docs/`](./docs) | The [documentation site](https://sekisho.mvd.im) — Fumadocs on Next.js, deployed to Cloudflare Workers via Workers Builds. |

## Development

Working on Sekisho itself requires Go 1.26+ (and Node with pnpm for the docs).

```sh
go test ./gateway/...   # gateway tests (go.work at the root)
docker build -t sekisho .   # container image, built with otelc
pnpm install && pnpm dev   # docs at http://localhost:3000
```

### Releasing

Push a `v*` tag to run [the release workflow](.github/workflows/release.yml). It attaches binaries for Linux, macOS and Windows (`amd64`, `arm64`) plus `checksums.txt` to a GitHub release, and pushes a multi-arch image to `ghcr.io/meesvandongen/sekisho`. Tags with a pre-release suffix (`v1.2.0-rc.1`) are published as pre-releases and do not move `latest`.

```sh
git tag v0.1.0 && git push origin v0.1.0
```
