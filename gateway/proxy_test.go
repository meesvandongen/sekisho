package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testOpenAPI = `openapi: 3.0.3
info:
  title: Proxy test
  version: "1"
servers:
  - url: https://unrelated.example/v2
paths:
  /items:
    servers:
      - url: https://another.example/other
    get:
      operationId: listItems
      responses:
        "200":
          description: ok
    post:
      operationId: createItem
      responses:
        "200":
          description: ok
  /items/{id}:
    get:
      operationId: getItem
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`

type testIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newTestIssuer(t testing.TB) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer.server.URL, "jwks_uri": issuer.server.URL + "/jwks",
			"authorization_endpoint":                issuer.server.URL + "/authorize",
			"token_endpoint":                        issuer.server.URL + "/token",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		}); err != nil {
			t.Error(err)
		}
	})
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testIssuer) sign(t testing.TB, overrides map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": i.server.URL, "aud": "proxy-test", "sub": "alice",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for name, value := range overrides {
		claims[name] = value
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func testConfig(t testing.TB, issuer *testIssuer, upstream string) Config {
	t.Helper()
	specPath := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(specPath, []byte(testOpenAPI), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{
		OpenAPIFile: specPath, UpstreamURL: upstream,
		OIDC: OIDCConfig{
			Issuer: issuer.server.URL, Audience: "proxy-test",
			JWKSURI: issuer.server.URL + "/jwks",
		},
		Policy: PolicyConfig{Routes: []RoutePolicyConfig{
			{Match: PolicyMatcher{OperationID: stringList{"listItems"}}, Check: &PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{Backend: "none"}},
			{Match: PolicyMatcher{OperationID: stringList{"createItem"}}, Check: &PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{Backend: "none"}},
			{Match: PolicyMatcher{OperationID: stringList{"getItem"}}, Check: &PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{Backend: "none"}},
		}},
	}
}

func setTestPolicy(t testing.TB, cfg *Config, operationID, expression string) {
	t.Helper()
	for index := range cfg.Policy.Routes {
		if slices.Equal(cfg.Policy.Routes[index].Match.OperationID, stringList{operationID}) {
			cfg.Policy.Routes[index].Check = &PolicyRule{CEL: expression}
			return
		}
	}
	t.Fatalf("test operationId %q has no route binding", operationID)
}

func startTestProxy(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func authedRequest(t *testing.T, method, target, token, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func sendRequest(t *testing.T, req *http.Request) (int, string, http.Header) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data), resp.Header.Clone()
}

func TestProxyRoutingOIDCAndStreaming(t *testing.T) {
	issuer := newTestIssuer(t)
	type received struct {
		path, query, body, auth, forwarded, originalForwarded string
	}
	calls := make(chan received, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		calls <- received{
			path: r.URL.Path, query: r.URL.RawQuery, body: string(body),
			auth: r.Header.Get("Authorization"), forwarded: r.Header.Get("X-Forwarded-For"),
			originalForwarded: r.Header.Get("Forwarded"),
		}
		fmt.Fprint(w, "upstream ok")
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL+"/base")
	cfg.OIDC.JWKSURI = ""
	setTestPolicy(t, &cfg, "getItem", `claims.sub == config.subject && method == "GET" && path_params.id == "abc" && host != ""`)
	cfg.Policy.Values = map[string]any{"subject": "alice"}
	proxy := startTestProxy(t, cfg)
	valid := issuer.sign(t, nil)

	req := authedRequest(t, http.MethodGet, proxy.URL+"/items/abc?trace=ok", valid, "not JSON")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("Forwarded", "for=10.0.0.1")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusOK || body != "upstream ok" {
		t.Fatalf("valid request: HTTP %d: %s", status, body)
	}
	got := <-calls
	if got.path != "/base/items/abc" || got.query != "trace=ok" || got.body != "not JSON" ||
		got.auth != "" || got.originalForwarded != "" || strings.Contains(got.forwarded, "10.0.0.1") {
		t.Fatalf("unexpected forwarded request: %+v", got)
	}

	cases := []struct {
		name, path, method, token string
		want                      int
	}{
		{"missing token", "/items/abc", http.MethodGet, "", http.StatusUnauthorized},
		{"malformed token", "/items/abc", http.MethodGet, "invalid", http.StatusUnauthorized},
		{"wrong audience", "/items/abc", http.MethodGet, issuer.sign(t, map[string]any{"aud": "other"}), http.StatusUnauthorized},
		{"wrong issuer", "/items/abc", http.MethodGet, issuer.sign(t, map[string]any{"iss": "https://other.invalid"}), http.StatusUnauthorized},
		{"expired", "/items/abc", http.MethodGet, issuer.sign(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}), http.StatusUnauthorized},
		{"not before", "/items/abc", http.MethodGet, issuer.sign(t, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}), http.StatusUnauthorized},
		{"unknown path", "/absent", http.MethodGet, "", http.StatusNotFound},
		{"unknown method", "/items", http.MethodDelete, "", http.StatusMethodNotAllowed},
		{"unlisted HEAD", "/items/abc", http.MethodHead, "", http.StatusMethodNotAllowed},
		{"unlisted OPTIONS", "/items/abc", http.MethodOptions, "", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := authedRequest(t, tc.method, proxy.URL+tc.path, tc.token, "")
			status, body, headers := sendRequest(t, req)
			if status != tc.want {
				t.Fatalf("HTTP %d, want %d: %s", status, tc.want, body)
			}
			if status == http.StatusUnauthorized && headers.Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("missing bearer challenge: %v", headers)
			}
		})
	}
	duplicate := authedRequest(t, http.MethodGet, proxy.URL+"/items/abc", valid, "")
	duplicate.Header.Add("Authorization", "Bearer "+valid)
	status, _, _ = sendRequest(t, duplicate)
	if status != http.StatusUnauthorized {
		t.Fatalf("duplicate Authorization: HTTP %d", status)
	}
	if len(calls) != 0 {
		t.Fatalf("%d unauthorized requests reached the upstream", len(calls))
	}
}

func TestPolicyBodyAndLimits(t *testing.T) {
	issuer := newTestIssuer(t)
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprint(w, string(body))
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxBodyBytes = 64
	setTestPolicy(t, &cfg, "createItem",
		`claims.sub == "alice" && headers["authorization"][0].startsWith("Bearer ") && query["tenant"][0] == config.tenant && path == "/items" && body.amount <= config.max_amount`)
	cfg.Policy.Values = map[string]any{"tenant": "blue", "max_amount": float64(5)}
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)

	tests := []struct {
		name, body, contentType string
		want                    int
	}{
		{"allowed", `{"amount":3}`, "application/json", http.StatusOK},
		{"denied", `{"amount":6}`, "application/json", http.StatusForbidden},
		{"duplicate keys", `{"amount":6,"amount":3}`, "application/json", http.StatusBadRequest},
		{"nested duplicate keys", `{"amount":3,"other":{"x":1,"x":2}}`, "application/json", http.StatusBadRequest},
		{"unsafe integer", `{"amount":9007199254740993}`, "application/json", http.StatusBadRequest},
		{"invalid UTF-8", string([]byte("{\"amount\":3,\"x\":\"\xff\"}")), "application/json", http.StatusBadRequest},
		{"invalid JSON", `{"amount":`, "application/json", http.StatusBadRequest},
		{"wrong content type", `{"amount":3}`, "text/plain", http.StatusUnsupportedMediaType},
		{"large body", strings.Repeat("x", 65), "application/json", http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := authedRequest(t, http.MethodPost, proxy.URL+"/items?tenant=blue", token, tc.body)
			req.Header.Set("Content-Type", tc.contentType)
			status, body, _ := sendRequest(t, req)
			if status != tc.want {
				t.Fatalf("HTTP %d, want %d: %s", status, tc.want, body)
			}
			if tc.want == http.StatusOK && body != tc.body {
				t.Fatalf("body changed during policy inspection: %q", body)
			}
		})
	}
	req := authedRequest(t, http.MethodPost, proxy.URL+"/items?tenant=%GG", token, `{"amount":3}`)
	req.Header.Set("Content-Type", "application/json")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid query: HTTP %d: %s", status, body)
	}
	req = authedRequest(t, http.MethodPost, proxy.URL+"/items?tenant=blue", token, strings.Repeat("x", 65))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	status, body, _ = sendRequest(t, req)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized body: HTTP %d: %s", status, body)
	}
	if got := forwarded.Load(); got != 1 {
		t.Fatalf("forwarded %d requests, want only the allowed request", got)
	}
}

func TestPolicyWorkLimits(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("over-budget policy reached upstream")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxBodyBytes = 128 << 10
	setTestPolicy(t, &cfg, "createItem", `body.items.exists(item, item == "never")`)
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)
	items := make([]string, 15_000)
	for index := range items {
		items[index] = "item"
	}
	data, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	req := authedRequest(t, http.MethodPost, proxy.URL+"/items", token, string(data))
	req.Header.Set("Content-Type", "application/json")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusForbidden {
		t.Fatalf("over-budget policy: HTTP %d: %s", status, body)
	}
	req = authedRequest(t, http.MethodPost, proxy.URL+"/items", token,
		strings.Repeat("[", maxJSONDepth+1)+"0"+strings.Repeat("]", maxJSONDepth+1))
	req.Header.Set("Content-Type", "application/json")
	status, body, _ = sendRequest(t, req)
	if status != http.StatusBadRequest {
		t.Fatalf("deep JSON body: HTTP %d: %s", status, body)
	}
}

func TestRawBodyPolicies(t *testing.T) {
	issuer := newTestIssuer(t)
	received := make(chan []byte, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		received <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxBodyBytes = 32
	setTestPolicy(t, &cfg, "createItem", `body_text.startsWith(config.prefix) && size(body_bytes) <= 20`)
	cfg.Policy.Values = map[string]any{"prefix": "publish:"}
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)

	for _, tc := range []struct {
		body []byte
		want int
	}{
		{[]byte("publish:data"), http.StatusNoContent},
		{[]byte("other:data"), http.StatusForbidden},
		{[]byte{0xff}, http.StatusBadRequest},
	} {
		req := authedRequest(t, http.MethodPost, proxy.URL+"/items", token, string(tc.body))
		req.Header.Set("Content-Type", "text/plain")
		status, body, _ := sendRequest(t, req)
		if status != tc.want {
			t.Fatalf("raw text policy: HTTP %d, want %d: %s", status, tc.want, body)
		}
	}
	if got := <-received; !bytes.Equal(got, []byte("publish:data")) || len(received) != 0 {
		t.Fatalf("unexpected forwarded text body: %q", got)
	}

	setTestPolicy(t, &cfg, "createItem", `size(body_bytes) == 2`)
	binaryProxy := startTestProxy(t, cfg)
	binary := []byte{0, 0xff}
	req := authedRequest(t, http.MethodPost, binaryProxy.URL+"/items", token, string(binary))
	req.Header.Set("Content-Type", "application/octet-stream")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusNoContent {
		t.Fatalf("raw binary policy: HTTP %d: %s", status, body)
	}
	if got := <-received; !bytes.Equal(got, binary) {
		t.Fatalf("binary body changed: %v", got)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	issuer := newTestIssuer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxConcurrentRequests = 1
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)
	firstRequest := authedRequest(t, http.MethodGet, proxy.URL+"/items", token, "")
	type outcome struct {
		status int
		err    error
	}
	firstResult := make(chan outcome, 1)
	go func() {
		resp, err := http.DefaultClient.Do(firstRequest)
		if err != nil {
			firstResult <- outcome{err: err}
			return
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		firstResult <- outcome{status: resp.StatusCode, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("first request did not reach upstream")
	}
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", token, "")
	status, _, headers := sendRequest(t, req)
	close(release)
	if status != http.StatusTooManyRequests || headers.Get("Retry-After") != "1" ||
		headers.Get("X-Proxy-Outcome") != string(outcomeRateLimited) {
		t.Fatalf("at capacity: HTTP %d, headers %v", status, headers)
	}
	if got := <-firstResult; got.err != nil || got.status != http.StatusNoContent {
		t.Fatalf("first request: HTTP %d: %v", got.status, got.err)
	}
}

func TestStreamingBodyLimit(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxBodyBytes = 64
	proxy := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodPost, proxy.URL+"/items", issuer.sign(t, nil), strings.Repeat("x", 65))
	req.ContentLength = -1
	status, body, headers := sendRequest(t, req)
	if status != http.StatusRequestEntityTooLarge ||
		headers.Get("X-Proxy-Outcome") != string(outcomeBodyTooLarge) {
		t.Fatalf("streamed oversized body: HTTP %d: %s", status, body)
	}
}

func TestHeaderLimit(t *testing.T) {
	cfg := Config{MaxHeaderBytes: 1024}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config = newHTTPServer(cfg, server.Config.Handler)
	server.Start()
	t.Cleanup(server.Close)
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Large", strings.Repeat("x", 16<<10))
	status, body, _ := sendRequest(t, req)
	if status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized headers: HTTP %d: %s", status, body)
	}
}

func TestUpstreamHeaderLimit(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", 16<<10))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxHeaderBytes = 1024
	proxy := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", issuer.sign(t, nil), "")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusBadGateway {
		t.Fatalf("upstream oversized headers: HTTP %d: %s", status, body)
	}
}

func TestAmbiguousPathsAreRejected(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("ambiguous path reached upstream")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL+"/base")
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)
	for _, path := range []string{
		"/items/a%2Fb", "/items/a%5Cb", "/items/%2e%2e", "/items/..",
	} {
		t.Run(path, func(t *testing.T) {
			req := authedRequest(t, http.MethodGet, proxy.URL+path, token, "")
			status, body, _ := sendRequest(t, req)
			if status != http.StatusBadRequest {
				t.Fatalf("ambiguous path: HTTP %d: %s", status, body)
			}
		})
	}
}
