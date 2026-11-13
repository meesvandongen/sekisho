package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkProxy(b *testing.B) {
	issuer := newTestIssuer(b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	b.Cleanup(upstream.Close)
	b.Setenv("SEKISHO_BENCH_SECRET", "benchmark-only-secret")
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") == tokenExchangeGrant {
			_, _ = io.WriteString(w,
				`{"access_token":"backend","token_type":"Bearer","issued_token_type":"`+accessTokenType+`","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"backend","token_type":"Bearer","expires_in":3600}`)
	}))
	b.Cleanup(tokenEndpoint.Close)
	token := issuer.sign(b, nil)
	base := testConfig(b, issuer, upstream.URL)
	disabled := false
	base.Audit.Enabled = &disabled

	cases := []struct {
		name, method, path, body, policy string
		status                           int
		audit                            bool
		grant                            string
	}{
		{"route_miss", "GET", "/unknown", "", "", http.StatusNotFound, false, ""},
		{"invalid_auth", "GET", "/items", "", "", http.StatusUnauthorized, false, ""},
		{"valid_forwarded", "GET", "/items", "", "", http.StatusNoContent, false, ""},
		{"claim_policy_allowed", "GET", "/items", "", `claims.sub == "alice"`, http.StatusNoContent, false, ""},
		{"claim_policy_denied", "GET", "/items", "", `claims.sub == "other"`, http.StatusForbidden, false, ""},
		{"json_policy", "POST", "/items", `{"allowed":true}`, `body.allowed == true`, http.StatusNoContent, false, ""},
		{"streamed_body_64KiB", "POST", "/items", strings.Repeat("x", 64<<10), "",
			http.StatusNoContent, false, ""},
		{"json_policy_64KiB", "POST", "/items", `{"padding":"` + strings.Repeat("x", 64<<10) + `"}`,
			`body.padding.size() == 65536`, http.StatusNoContent, false, ""},
		{"cached_backend_token", "GET", "/items", "", "", http.StatusNoContent, false, "client_credentials"},
		{"token_exchange", "GET", "/items", "", "", http.StatusNoContent, false, "token_exchange"},
		{"audit_json", "GET", "/items", "", "", http.StatusNoContent, true, ""},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			cfg := base
			if tc.policy != "" {
				operation := "listItems"
				if tc.method == http.MethodPost {
					operation = "createItem"
				}
				setTestPolicy(b, &cfg, operation, tc.policy)
			}
			if tc.audit {
				cfg.Audit.Enabled = nil
			}
			if tc.grant != "" {
				cfg.BackendAuth = BackendAuthConfig{
					GrantType: tc.grant, TokenURL: tokenEndpoint.URL,
					ClientID: "benchmark-client", ClientAuth: "client_secret_basic",
					ClientSecretEnv: "SEKISHO_BENCH_SECRET",
				}
				cfg.Policy.Routes[0].Auth.Backend = "default"
			}
			handler, err := newProxy(context.Background(), cfg)
			if err != nil {
				b.Fatal(err)
			}
			if tc.audit {
				handler.auditLogger = slog.New(slog.NewJSONHandler(io.Discard, nil))
			}
			template := httptest.NewRequest(tc.method, "http://proxy.test"+tc.path, nil)
			if tc.name == "invalid_auth" {
				template.Header.Set("Authorization", "Bearer invalid")
			} else {
				template.Header.Set("Authorization", "Bearer "+token)
			}
			if tc.body != "" && tc.policy != "" {
				template.Header.Set("Content-Type", "application/json")
			}
			request := func() *http.Request {
				req := template.Clone(context.Background())
				if tc.body != "" {
					req.Body = io.NopCloser(strings.NewReader(tc.body))
					req.ContentLength = int64(len(tc.body))
				}
				return req
			}
			// Prime the JWKS cache and any connections before measuring the steady state.
			warm := httptest.NewRecorder()
			handler.ServeHTTP(warm, request())
			if warm.Code != tc.status {
				b.Fatalf("warm-up: HTTP %d, want %d", warm.Code, tc.status)
			}
			b.ReportAllocs()
			if tc.body != "" {
				b.SetBytes(int64(len(tc.body)))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, request())
				if w.Code != tc.status {
					b.Fatalf("HTTP %d, want %d", w.Code, tc.status)
				}
			}
			b.StopTimer()
		})
	}
}

func BenchmarkProxyParallel(b *testing.B) {
	issuer := newTestIssuer(b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	b.Cleanup(upstream.Close)
	cfg := testConfig(b, issuer, upstream.URL)
	disabled := false
	cfg.Audit.Enabled = &disabled
	cfg.MaxConcurrentRequests = max(64, runtime.GOMAXPROCS(0)*4)
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	template := httptest.NewRequest(http.MethodGet, "http://proxy.test/items", nil)
	template.Header.Set("Authorization", "Bearer "+issuer.sign(b, nil))
	warm := httptest.NewRecorder()
	handler.ServeHTTP(warm, template.Clone(context.Background()))
	if warm.Code != http.StatusNoContent {
		b.Fatalf("warm-up: HTTP %d", warm.Code)
	}
	var failures atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, template.Clone(context.Background()))
			if w.Code != http.StatusNoContent {
				failures.Add(1)
			}
		}
	})
	if failures.Load() != 0 {
		b.Fatalf("%d parallel requests failed", failures.Load())
	}
}

func BenchmarkProxyHTTP(b *testing.B) {
	issuer := newTestIssuer(b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	b.Cleanup(upstream.Close)
	cfg := testConfig(b, issuer, upstream.URL)
	disabled := false
	cfg.Audit.Enabled = &disabled
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	server := httptest.NewServer(handler)
	b.Cleanup(server.Close)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/items", nil)
	if err != nil {
		b.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+issuer.sign(b, nil))
	client := &http.Client{Timeout: 5 * time.Second}
	send := func() {
		resp, err := client.Do(request.Clone(context.Background()))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			resp.Body.Close()
			b.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != http.StatusNoContent {
			b.Fatalf("HTTP %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
	}
	send()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		send()
	}
}

func BenchmarkPolicyShortCircuit(b *testing.B) {
	issuer := newTestIssuer(b)
	cfg := testConfig(b, issuer, "http://127.0.0.1:1")
	disabled := false
	cfg.Audit.Enabled = &disabled
	cfg.Policy.Routes[1].Check = &PolicyRule{All: []PolicyRule{
		{CEL: `claims.sub == "never"`},
		{CEL: `body.allowed == true`},
	}}
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	payload := strings.Repeat("x", 64<<10)
	template := httptest.NewRequest(http.MethodPost, "http://proxy.test/items", nil)
	template.Header.Set("Authorization", "Bearer "+issuer.sign(b, nil))
	template.Header.Set("Content-Type", "text/plain")
	send := func() {
		req := template.Clone(context.Background())
		req.Body = io.NopCloser(strings.NewReader(payload))
		req.ContentLength = int64(len(payload))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden ||
			w.Header().Get("X-Proxy-Outcome") != string(outcomePolicyDenied) {
			b.Fatalf("short-circuited policy returned HTTP %d: %s", w.Code, w.Body.String())
		}
	}
	send()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		send()
	}
}
