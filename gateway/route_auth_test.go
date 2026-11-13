package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPerRouteScopesBackendProfilesAndStripping(t *testing.T) {
	issuer := newTestIssuer(t)
	type seenRequest struct{ path, authorization, forwardedAuth, originalAuth, proxyAuth string }
	received := make(chan seenRequest, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- seenRequest{
			r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Forwarded-Authorization"),
			r.Header.Get("X-Original-Authorization"), r.Header.Get("Proxy-Authorization"),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("SEKISHO_SCOPE_TEST_SECRET", "test-secret")
	forms := make(chan url.Values, 4)
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		forms <- r.PostForm
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":120}`,
			r.PostForm.Get("scope")+"-backend-token")
	}))
	t.Cleanup(tokenEndpoint.Close)

	cfg := testConfig(t, issuer, upstream.URL)
	cfg.BackendAuthProfiles = map[string]BackendAuthConfig{
		"read": {
			GrantType: "client_credentials", TokenURL: tokenEndpoint.URL, ClientID: "client",
			ClientAuth: "client_secret_basic", ClientSecretEnv: "SEKISHO_SCOPE_TEST_SECRET",
			Scope: []string{"items:read"},
		},
		"write": {
			GrantType: "client_credentials", TokenURL: tokenEndpoint.URL, ClientID: "client",
			ClientAuth: "client_secret_basic", ClientSecretEnv: "SEKISHO_SCOPE_TEST_SECRET",
			Scope: []string{"items:write"},
		},
	}
	cfg.Policy.Routes[0].Auth = RouteAuthConfig{Backend: "read", RequiredScopes: []string{"items:read"}}
	cfg.Policy.Routes[1].Auth = RouteAuthConfig{Backend: "write", RequiredScopes: []string{"items:write"}}
	cfg.Policy.Routes[2].Auth = RouteAuthConfig{Backend: "none", RequiredScopes: []string{"items:read"}}
	proxy := startTestProxy(t, cfg)

	tokens := []struct {
		method, path string
		claims       map[string]any
		want         int
		backend      string
	}{
		{http.MethodGet, "/items", map[string]any{"scope": "items:read"}, 204, "Bearer items:read-backend-token"},
		{http.MethodPost, "/items", map[string]any{"scp": []string{"items:write"}}, 204, "Bearer items:write-backend-token"},
		{http.MethodPost, "/items", map[string]any{"scp": "items:write"}, 204, "Bearer items:write-backend-token"},
		{http.MethodGet, "/items", map[string]any{"scope": "items:read"}, 204, "Bearer items:read-backend-token"},
		{http.MethodGet, "/items/abc", map[string]any{"scope": "items:read"}, 204, ""},
		{http.MethodPost, "/items", map[string]any{"scope": "items:read"}, 403, ""},
		{http.MethodGet, "/items", nil, 403, ""},
		{http.MethodGet, "/items", map[string]any{"scope": 42}, 401, ""},
	}
	for _, tc := range tokens {
		req := authedRequest(t, tc.method, proxy.URL+tc.path, issuer.sign(t, tc.claims), "")
		req.Header.Set("X-Forwarded-Authorization", "Bearer caller-secret")
		req.Header.Set("X-Original-Authorization", "Bearer caller-secret")
		req.Header.Set("Proxy-Authorization", "Bearer caller-secret")
		status, body, headers := sendRequest(t, req)
		if status != tc.want {
			t.Fatalf("%s %s: HTTP %d, want %d: %s", tc.method, tc.path, status, tc.want, body)
		}
		if status == http.StatusForbidden && headers.Get("X-Proxy-Outcome") != string(outcomeInsufficientScope) {
			t.Fatalf("missing scope outcome: %v", headers)
		}
		if status == http.StatusUnauthorized && headers.Get("X-Proxy-Outcome") != string(outcomeClaimsInvalid) {
			t.Fatalf("invalid scope outcome: %v", headers)
		}
		if status == http.StatusNoContent {
			got := <-received
			if got.authorization != tc.backend || got.forwardedAuth != "" ||
				got.originalAuth != "" || got.proxyAuth != "" {
				t.Fatalf("unsafe backend request: %+v", got)
			}
		}
	}
	if len(received) != 0 || len(forms) != 2 {
		t.Fatalf("unexpected backend traffic: forwarded=%d token requests=%d", len(received), len(forms))
	}
	read := <-forms
	write := <-forms
	if read.Get("scope") != "items:read" || write.Get("scope") != "items:write" {
		t.Fatalf("backend token scopes were not least-privilege: %v %v", read, write)
	}
}

func TestTokenExchangeCacheIsBoundedByTokenAndProfile(t *testing.T) {
	issuer := newTestIssuer(t)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("SEKISHO_EXCHANGE_CACHE_SECRET", "test-secret")
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		count := calls.Add(1)
		if r.PostForm.Get("subject_token") == "" {
			t.Error("exchange did not send subject token")
		}
		fmt.Fprintf(w,
			`{"access_token":%q,"token_type":"Bearer","issued_token_type":"%s","expires_in":120}`,
			fmt.Sprintf("backend-%d", count), accessTokenType)
	}))
	t.Cleanup(endpoint.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.BackendAuthProfiles = map[string]BackendAuthConfig{
		"exchange": {
			GrantType: "token_exchange", TokenURL: endpoint.URL, ClientID: "client",
			ClientAuth: "client_secret_basic", ClientSecretEnv: "SEKISHO_EXCHANGE_CACHE_SECRET",
			Cache: CacheConfig{TTLSeconds: 60, MaxEntries: 1},
		},
	}
	cfg.Policy.Routes[1].Auth.Backend = "exchange"
	proxy := startTestProxy(t, cfg)
	first := issuer.sign(t, map[string]any{"sub": "first"})
	second := issuer.sign(t, map[string]any{"sub": "second"})
	for _, token := range []string{first, first, second, first} {
		req := authedRequest(t, http.MethodPost, proxy.URL+"/items", token, "")
		status, body, _ := sendRequest(t, req)
		if status != http.StatusNoContent {
			t.Fatalf("exchange cache: HTTP %d: %s", status, body)
		}
	}
	if calls.Load() != 3 || upstreamCalls.Load() != 4 {
		t.Fatalf("cache did not reuse/evict by subject token: endpoint=%d upstream=%d",
			calls.Load(), upstreamCalls.Load())
	}
}

func TestInvalidBackendProfileConfiguration(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	cfg.BackendAuthProfiles = map[string]BackendAuthConfig{"none": {GrantType: "client_credentials"}}
	if _, err := newProxy(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved backend profile accepted: %v", err)
	}
	cfg.BackendAuthProfiles = map[string]BackendAuthConfig{"exchange": {
		GrantType: "token_exchange", TokenURL: "http://127.0.0.1:8081/token",
		ClientID: "client", ClientAuth: "client_secret_basic", ClientSecretEnv: "CACHE_TEST",
		Cache: CacheConfig{TTLSeconds: 301},
	}}
	if _, err := newProxy(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "ttl_seconds") {
		t.Fatalf("unbounded cache accepted: %v", err)
	}
	cfg.BackendAuthProfiles = make(map[string]BackendAuthConfig)
	for index := range 5 {
		cfg.BackendAuthProfiles[fmt.Sprintf("exchange_%d", index)] = BackendAuthConfig{
			GrantType: "token_exchange", TokenURL: "http://127.0.0.1:8081/token",
			ClientID: "client", ClientAuth: "client_secret_basic", ClientSecretEnv: "CACHE_TEST",
			Cache: CacheConfig{TTLSeconds: 60, MaxEntries: 256},
		}
	}
	if _, err := newProxy(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "caches exceed") {
		t.Fatalf("aggregate backend cache budget was not enforced: %v", err)
	}
}
