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
  <a href="https://sekisho.mvd.im/docs">Documentation</a> ·
  <a href="https://sekisho.mvd.im/docs/quickstart">Quickstart</a> ·
  <a href="https://sekisho.mvd.im/docs/configuration">Configuration</a>
</p>

---

Sekisho is an OIDC-aware policy gateway. It verifies inbound JWTs, requires an explicit [CEL](https://cel.dev) policy binding for every operation in a local OpenAPI 3 spec, and forwards allowed requests to a single upstream — using least-privilege backend credentials, never the caller's token.

```sh
cd gateway
go tool otelc go build -buildvcs=false -o sekisho .
./sekisho -config examples/config.json
```

Requires Go 1.26+. See the [quickstart](https://sekisho.mvd.im/docs/quickstart) for secrets and OpenTelemetry settings.

## Repository

| Path | Contents |
| --- | --- |
| [`gateway/`](./gateway) | The Go gateway, its tests and [example configuration](./gateway/examples). |
| [`docs/`](./docs) | The [documentation site](https://sekisho.mvd.im) — Fumadocs on Next.js, deployed to Cloudflare Workers via Workers Builds. |

```sh
go test ./gateway/...   # gateway tests (go.work at the root)
pnpm install && pnpm dev   # docs at http://localhost:3000
```
