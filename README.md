# Sekisho

An OIDC-aware policy gateway. Sekisho verifies inbound signed JWTs, requires an explicit authorization binding for every operation in a local OpenAPI 3 specification, and forwards allowed requests to one configured upstream. Policies compose reusable CEL checks; routes can select least-privilege backend credentials and optional identity lookups.

## Run

Requires Go 1.26 or newer. Copy and edit [examples/config.json](./examples/config.json) and [examples/api.yaml](./examples/api.yaml) for your issuer and API. Supply `BACKEND_CLIENT_SECRET` from a secret manager, then build with the pinned `otelc` tool and run:

```sh
go tool otelc go build -buildvcs=false -o sekisho .
OTEL_SERVICE_NAME=sekisho \
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
OTEL_LOGS_EXPORTER=none \
./sekisho -config examples/config.json
```

`otelc` is pinned in `go.mod`; `go tool otelc go build` injects the SDK and supported instrumentations at build time. Plain `go run .` or `go build .` still runs the proxy but produces no OTel signals. Paths in the JSON config (the OpenAPI file, CEL files, and private key files) are relative to the config file. Unknown or duplicate config fields, invalid policies, missing credentials for selected profiles, uncovered OpenAPI operations, and invalid specs prevent startup. Changes require a restart.

Every listed operation requires `Authorization: Bearer <JWT>`. The proxy verifies the signature, exact issuer, configured audience, expiry, and signing-algorithm allowlist. It rejects missing, malformed, or repeated Authorization headers. `oidc.jwks_uri` may be set to bypass discovery; otherwise the proxy discovers JWKS from `oidc.issuer` at startup. Keys are cached by the OIDC verifier. The default algorithm allowlist is `["RS256"]`; `oidc.algorithms` can explicitly allow other supported asymmetric algorithms. Opaque inbound tokens are not supported. An optional RFC 7662 introspection check can supplement local JWT verification for operations that request it.

OpenAPI is a **path/method allowlist**, not request or response schema validation. Its `servers` entries are ignored for incoming route matching. Set `upstream_url` separately: an upstream URL ending in `/v1` forwards public `/items` to `/v1/items`. The spec must contain the public paths; external `$ref` files and URLs are disabled. Unknown paths return 404, unknown methods 405. Encoded path separators, backslashes, and `.`/`..` path segments are rejected to avoid route interpretation differences.

## Policies

`policy.routes` is an array of **exactly one binding per OpenAPI method/path**. A binding's `match` uses either `{"operation_id":"..."}` or `{"path":"/items/{id}","method":"GET"}` (the OpenAPI *template*, not a concrete URL). `operationId` is optional in OpenAPI; path/method works without it. Missing, duplicate, or unknown bindings fail startup. Each binding must have a `check` and an explicit `auth.backend`: `"none"`, `"default"` (requires top-level `backend_auth`), or a name in `backend_auth_profiles`. No policy is implied by listing an operation in OpenAPI, and there is no permissive fallback. The earlier `policy.default`/`policy.operations` format is deliberately rejected; migrate every operation to an explicit route binding.

`policy.definitions` contains named reusable rules. Every rule specifies exactly one of `cel`, `file`, `ref`, `all`, `any`, or `not`. `all`/`any` require at least one child and short-circuit in order; `not` wraps one rule. References may carry `params`, which override the binding's `params` within that reference; named rules may reference other named rules, but cycles and excessive expansions fail startup. CEL files are UTF-8, at most 64 KiB, and resolved relative to the JSON config. Rules compile and are type-checked once at startup. For example:

```json
{
  "definitions": {
    "publisher": {"cel": "claims.sub == params.subject"},
    "amount": {"file": "policies/amount.cel"}
  },
  "routes": [
    {
      "name": "publish_item",
      "match": {"operation_id": "createItem"},
      "check": {"all": [
        {"ref": "publisher", "params": {"subject": "alice"}},
        {"ref": "amount", "params": {"max": 5}}
      ]},
      "auth": {"backend": "write", "required_scopes": ["items:write"]},
      "on_deny": {
        "response": {"status": 403, "code": "package_denied", "detail": "Publishing policy denied this item."},
        "log": {"reason": "publishing_policy", "level": "warn", "message": "publishing policy denied"}
      }
    }
  ]
}
```

The excerpt shows one binding; real configurations must cover **every** OpenAPI operation. A `ref` with `params` provides reuse without adding user-defined CEL functions or unbounded recursion. The same binding-level `on_deny` applies when any child returns false. Errors during evaluation or data lookup are **not** turned into custom denials: they fail closed with their own stable code. `on_deny.response.status` can be 401, 403, or 404 (default 403); `code` and `detail` are bounded static text. `on_deny.log.reason`, `message` and `level` (`info`, `warn`, `error`) customize the structured audit event for a false policy decision. Never interpolate caller input into denial text or logs.

The following variables are available to expressions:

| Variable | Value |
| --- | --- |
| `claims` | Verified JWT claims as a map |
| `headers` | Lowercase request header names mapped to lists of values, including the original `authorization` |
| `query` | Query names mapped to lists of values |
| `path_params` | OpenAPI path parameter names and values |
| `body` | Parsed JSON value, or `null` for an empty body |
| `body_bytes`, `body_text` | Raw bytes, or UTF-8 text (for non-JSON bodies too) |
| `method`, `path`, `host` | Request method, decoded path, and Host |
| `operation` | The **OpenAPI Operation Object** as a map with OpenAPI JSON keys, including `tags`, `parameters`, `responses`, `operationId` when present, and extensions |
| `operation_id` | Operation ID string (empty when absent) |
| `config`, `params` | Shared `policy.values` map and binding/reference parameters |
| `userinfo`, `introspection` | Optional JSON objects from the configured identity endpoints; fetched only when evaluated |

For example:

```cel
claims.sub == "publisher" &&
"tenant" in query && query["tenant"][0] == config.tenant &&
"authorization" in headers && headers["authorization"].size() == 1 &&
body.package == config.package &&
operation.tags.exists(tag, tag == "publish") && operation_id == "createItem"
```

Inputs are resolved lazily and memoized within a request. A body is buffered **only** if evaluating a selected CEL branch actually accesses `body`, `body_bytes`, or `body_text`; otherwise it streams to the upstream. JSON parsing happens only for `body`, which requires a JSON content type (`application/json` or `+json`). JSON rules reject invalid UTF-8, duplicate object keys, excessive nesting or value counts, and numbers outside the safe double-precision range. `body_text` also requires valid UTF-8; `body_bytes` accepts binary data. CEL numeric JSON values are doubles; use integer minor units below 2^53 or strings when exact decimal semantics matter. Missing fields, lookup failures, and evaluation errors deny the request. Each CEL evaluation has a 10,000-unit cost cap; the expanded policy graph is limited to 256 nodes and 16 levels per route (4,096 compiled nodes in the config). Large OpenAPI operations are only materialized if referenced and have a 256 KiB per-operation and 8 MiB total serialized limit.

## Backend authentication

Each route's `auth.required_scopes` is an optional **all-of** list of incoming JWT permissions from the verified `scope` string or `scp` string/array. A missing scope returns 403 `insufficient_scope` before evaluating the policy, making downstream identity lookups unnecessary. A route selecting backend `"none"` forwards **no** inbound Authorization; `"default"` selects top-level `backend_auth`; other names select a profile from `backend_auth_profiles` with its own scope, audience/resource, credentials and cache. Configure separate read/write profiles rather than requesting their union for every route. The inbound bearer token is **never forwarded as the upstream Authorization header**. The proxy also strips `Proxy-Authorization`, `X-Forwarded-Authorization`, and `X-Original-Authorization`, as well as inbound forwarding and correlation headers. Supported backend grants:

- `client_credentials`: acquire and cache a bearer token until shortly before expiry.
- `token_exchange`: exchange the verified inbound JWT as `subject_token` using RFC 8693. By default this runs once per request; set `cache.ttl_seconds` (1..300) to enable a bounded per-profile, per-inbound-token cache, optionally with `cache.max_entries` (1..256, default 128). Entries expire no later than either JWT or backend token; errors are not cached. Set `subject_token_type` to `urn:ietf:params:oauth:token-type:id_token` if the issuer provides ID tokens instead of access tokens. Optional `requested_token_type`, `audience`, `resource`, and `scope` are sent to the token endpoint. The response must declare the requested `issued_token_type`.

Both grants require `token_url`, `client_id`, and one `client_auth`; the top-level default and each named profile have the same schema:

- `client_secret_basic` (recommended) or `client_secret_post`: read the secret at startup from the environment variable named by `client_secret_env`; never put its value in the JSON file.
- `private_key_jwt`: sign a short-lived RS256 client assertion (RFC 7523) with a PEM RSA private key of at least 2048 bits from `private_key_file`. An optional `key_id` becomes the JWT `kid`. Keep the key outside source control.

Example token-exchange configuration:

```json
{
  "grant_type": "token_exchange",
  "token_url": "https://issuer.example/oauth2/token",
  "client_id": "backend-client",
  "client_auth": "private_key_jwt",
  "private_key_file": "client-key.pem",
  "key_id": "backend-key-1",
  "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
  "audience": "backend-api"
}
```

## Optional identity data

The `identity.userinfo` and `identity.introspection` settings are **independent** and are never queried merely because they are configured. The selected policy must access `userinfo` or `introspection`. CEL short-circuiting skips unreachable lookups. Both require explicit HTTP(S) URLs without query strings; responses must be JSON objects no larger than 16 KiB, and the HTTP client has a 10-second timeout. For example:

```json
"identity": {
  "userinfo": {
    "url": "https://issuer.example/userinfo",
    "cache": {"ttl_seconds": 30, "max_entries": 128}
  },
  "introspection": {
    "url": "https://issuer.example/oauth2/introspect",
    "client_id": "inspector",
    "client_auth": "client_secret_basic",
    "client_secret_env": "INTROSPECTION_CLIENT_SECRET",
    "cache": {"ttl_seconds": 30, "max_entries": 128}
  }
}
```

`userinfo` sends the verified inbound JWT as a bearer token in a GET request and **requires the response `sub` to match** the verified JWT subject. `introspection` performs an authenticated RFC 7662 POST (never a token-in-URL GET), requires `active: true`, and checks `sub` and `exp` when present; `token_type_hint` is optional if your provider requires one. Introspection supports the same `client_secret_basic`, `client_secret_post`, and `private_key_jwt` credential fields as backend authentication. It is an additional check on a JWT already validated locally, not a way to accept opaque tokens. Lookup failures or mismatched identities deny access even when a CEL `any` or `||` could otherwise return true.

Cache TTL defaults to **zero (off)** and is capped at 300 seconds, with at most 256 entries per endpoint; entries are keyed by a SHA-256 digest of the inbound token, not a raw token string. Successful responses are cached no longer than the verified JWT expiry and the introspection expiry (if present). Concurrent lookups for the same token are coalesced. Positive caching can delay revocation visibility by up to the configured TTL: leave it disabled or choose a short TTL when immediate revocation matters. Configuration of an unused lookup causes no requests and does not load its client secret. Backend auth is limited to 64 named profiles and 1,024 token-exchange cache entries across profiles.

## Testing policies offline

Run the same compiled policy/route/scope logic against fixtures without starting a listener, contacting the issuer, fetching backend tokens, or loading client secrets:

```sh
go run -buildvcs=false . -config examples/config.json -test-policies policy-tests.json
```

The fixture path is relative to the config file. [examples/policy-tests.json](./examples/policy-tests.json) includes allowed, denied, missing-scope, and path/method-selector cases. Each case supplies `name`, HTTP `method`/concrete `path` (including query), optional `host`, `headers`, `content_type`, raw UTF-8 `body` or `body_base64`, simulated verified `claims`, optional `userinfo`/`introspection` objects, and `expected`. Allowed expectations specify `{"allowed":true,"backend_auth":"read"}`; denials specify `{"allowed":false,"status":403,"code":"package_denied"}`. Output is one JSON result per case with `passed`; the command exits nonzero on any mismatch. Files are limited to 1 MiB and 256 cases.

**Fixtures are not authentication tests.** Supplied claims stand in for a verified JWT; provided identity objects stand in for endpoint responses and are checked for matching subject/active/expiry, but no network or cryptographic verification occurs. Use the signed-token integration tests for those paths. Missing identity fixture data fails closed if a selected CEL branch needs it.

## Outcomes and audit trail

Proxy-generated failures return `application/problem+json` with a stable `code`, HTTP `status`, and an optional `trace_id` when an instrumented build records a request span:

```json
{"type":"about:blank","title":"Forbidden","status":403,"code":"policy_denied","trace_id":"0123456789abcdef0123456789abcdef"}
```

`X-Proxy-Outcome` is set on **every** response. A successful forwarding has `forwarded`; a backend-generated 4xx or 5xx retains its original body/status but has `upstream_rejected` or `upstream_failure`. `X-Proxy-Trace-ID` correlates the response with traces and audit records when the request has an OTel span. Neither header is trusted from clients or upstreams.

| Phase | Codes and meaning |
| --- | --- |
| Admission/routing | `rate_limited` (429), `body_too_large` (413), `ambiguous_path` (400), `route_not_found` (404), `method_not_allowed` (405), `routing_error` (500) |
| Authentication | `auth_missing` (401), `auth_malformed` (401), `auth_expired` (401), `auth_invalid` (401), `claims_invalid` (401), `insufficient_scope` (403); `auth_invalid` groups signature, issuer, audience, and other verification failures |
| Policy | `policy_denied` (403), `policy_error` (403), `claims_invalid` (401), `invalid_query` (400), `invalid_json` (400), `invalid_body_text` (400), `body_read_error` (400), `unsupported_media_type` (415) |
| Optional identity data | `userinfo_unavailable`/`userinfo_invalid` (502), `userinfo_subject_mismatch` (401), `introspection_unavailable`/`introspection_invalid` (502), `introspection_subject_mismatch`/`token_inactive` (401) |
| Backend credential | `backend_token_unavailable` (502), `backend_token_rejected` (502), `backend_token_invalid` (502), `backend_assertion_failed` (502) |
| Forwarding | `upstream_unavailable` (502), `upstream_timeout` (504), `upstream_stream_aborted` (a stream that failed after headers), or the upstream response codes above |

Structured audit events are **on by default** and emitted as one JSON line per request on stderr; set `"audit": {"enabled": false}` to opt out. Events include the outcome code, HTTP status, decision phase, method, OpenAPI route template/operation ID, optional binding name and static deny reason, elapsed milliseconds, optional trace ID, and a `dependency_status` for rejected token/identity endpoints. After successful verification they also include `subject_sha256`, the SHA-256 hash of `issuer + NUL + subject`. They exclude raw JWTs, request bodies, headers, query strings, and path parameter values. The hash is a correlation aid, **not anonymous**; protect and retain these logs accordingly. Invalid tokens never contribute an identity hash. Operators can distinguish a rejected policy from a policy-evaluation error, or an identity endpoint failure from an unreachable upstream, without exposing server error text to callers. Audit writes are best effort: sink errors are logged, not retroactively converted into request failures. Use a durable log collector if audit retention is required.

## OpenTelemetry

The pinned [Go compile-time instrumentation tool](https://opentelemetry.io/docs/zero-code/go/compile-time/) initializes the SDK **before** the proxy reads its JSON file. Configure OTel with environment variables set *before launching the binary*, not an `otel` object in the JSON config:

```sh
OTEL_SERVICE_NAME=sekisho
OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.internal.example:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=otlp
OTEL_LOGS_EXPORTER=none
```

Standard per-signal endpoints, exporter headers, sampling, resources, batch and interval settings also work. `OTEL_SDK_DISABLED=true` disables the injected SDK and hooks. `OTEL_GO_ENABLED_INSTRUMENTATIONS` and `OTEL_GO_DISABLED_INSTRUMENTATIONS` select compiled-in hooks at runtime; `nethttp` controls both client and server HTTP hooks. With the SDK disabled, or with a plain build instead of `otelc`, audit and outcome responses still work but no spans or metrics are exported. Disabling only the trace exporter does not disable metrics.

The compile-time HTTP server hook creates the request span. The proxy adds its stable outcome, decision phase, response status, operation ID and OpenAPI route template, and names the span `METHOD /openapi/{template}`. The HTTP client hook adds dependency spans and propagates context to upstreams. Caller baggage is removed before backend authentication and forwarding. JWKS refreshes may form separate traces because the OIDC library detaches its key-fetch context. No second, manually configured OTel provider or HTTP transport instrumentation is used.

**Privacy:** default `otelc` HTTP spans can contain `url.path`, `url.query` and outbound `url.full`. Its query redaction covers a short, case-sensitive set of signature keys, **not** arbitrary `token` or `secret` parameters; debug logging can print an unredacted URL. Do not place secrets in request paths, query strings, or token-endpoint URLs. The standard HTTP hooks do not include Authorization headers or bodies by default. If your deployment cannot permit URL attributes, disable `nethttp` (which also removes the automatic request/client spans) or supply custom instrumentation rules. The proxy-specific metrics and audit fields remain bounded and do not contain raw URLs.

Metrics remain `proxy.requests` (counter), `proxy.request.duration` (seconds histogram with sub-second buckets), and `proxy.requests.active` (up/down counter). Request count and latency use OpenAPI route templates (or `unmatched`), normalized HTTP methods, HTTP status, and outcome codes. `otelc` also collects Go runtime metrics by default. Audit logs are JSON on stderr, not an OTLP log exporter; ship them separately and correlate using `trace_id`. `otelc` flushes telemetry on SIGINT/SIGTERM, but its signal hook can run before the proxy finishes draining in-flight requests; allow a collector grace period and do not rely on the last span as a durable audit record.

## Performance benchmarks

```sh
go test ./... -run '^$' -bench '^BenchmarkProxy' -benchmem -benchtime=1s -count=3
OTELC_INTEGRATION_TEST=1 go test ./... -run '^TestCompileTimeOTLP$' -count=1
go test -race ./...
```

The benchmarks prime the JWKS cache, use local test upstream/token servers, and cover route rejection, invalid/valid bearer tokens, claims and JSON-body policies, 64 KiB streamed versus parsed bodies, cached client credentials, token exchange, and JSON audit encoding. `BenchmarkPolicyShortCircuit` times a composite policy that denies before touching a 64 KiB body. `audit_json` writes to `io.Discard` to measure encoding rather than disk throughput. Plain `go test` measures without injected hooks; `BenchmarkProxyHTTP` covers the HTTP server path, whereas other `BenchmarkProxy` cases call the handler directly. To measure the instrumented build, run an external load generator against the `go tool otelc go build` binary with a representative collector. `otelc` v1.2.0 currently fails when instrumenting Go's generated test main with `otelc go test` in this environment; the opt-in integration test above uses a plain test runner and an instrumented subprocess instead. Compare `ns/op`, `B/op`, and `allocs/op` for the *same* machine and settings; `BenchmarkProxyParallel` measures concurrent throughput. These are steady-state local measurements, **not** a substitute for load testing the real issuer, collector, TLS, ingress, and upstream under production latency and rate limits. Do not compare race-enabled measurements to ordinary benchmark results.

## Limits and deployment

Defaults: 32 KiB inbound/response headers, 1 MiB request body, 64 active requests, 10,000 CEL cost units per leaf, 256 expanded policy nodes per route, 64 JSON nesting levels, and 20,000 JSON values. Configure `max_header_bytes`, `max_body_bytes`, and `max_concurrent_requests` in JSON. Known oversized bodies are rejected before forwarding; streamed bodies are capped as they are read. Response bodies are streamed. OpenAPI files are limited to 8 MiB (local references supported; external references disabled); issuer/JWKS responses are capped at 1 MiB, token responses at 64 KiB, and identity responses at 16 KiB. The injected SDK's batch queue is bounded and configurable with standard OTel environment variables. Header read timeout is 5 seconds; request read/write timeouts are 60 seconds; upstream response-header timeout is 30 seconds; identity/token HTTP timeout is 10 seconds.

Use HTTPS for the issuer, token endpoint, upstream, and collector in production. The listener serves plain HTTP; terminate public TLS at a trusted ingress or add TLS termination. Do not trust caller-supplied Host or forwarding headers in policies; the proxy removes inbound forwarding headers before setting its own. The audit sink and collector must be provisioned for expected request volume.

```sh
go test ./...
go tool otelc go build -buildvcs=false -o sekisho .
```
