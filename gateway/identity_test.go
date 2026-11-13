package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdentityLookupsAreLazyAndCached(t *testing.T) {
	issuer := newTestIssuer(t)
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	var userinfoCalls, introspectionCalls atomic.Int32
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userinfoCalls.Add(1)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Error("userinfo request did not use an inbound bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sub":"alice","team":"trusted"}`)
	}))
	t.Cleanup(userinfo.Close)
	t.Setenv("SEKISHO_INTROSPECTION_SECRET", "introspection-secret")
	introspection := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		introspectionCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		clientID, secret, basic := r.BasicAuth()
		if !basic || clientID != "inspector" || secret != "introspection-secret" ||
			r.Method != http.MethodPost || r.Form.Get("token") == "" ||
			r.Form.Get("token_type_hint") != "access_token" || r.URL.RawQuery != "" {
			t.Error("introspection request is not an authenticated RFC 7662 POST")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(w, `{"active":true,"sub":"alice","scope":"items:read","exp":%d}`,
			time.Now().Add(2*time.Minute).Unix())
	}))
	t.Cleanup(introspection.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.Identity = IdentityConfig{
		Userinfo: &UserinfoConfig{
			URL: userinfo.URL, Cache: CacheConfig{TTLSeconds: 60, MaxEntries: 1},
		},
		Introspection: &IntrospectionConfig{
			URL: introspection.URL, ClientID: "inspector", ClientAuth: "client_secret_basic",
			ClientSecretEnv: "SEKISHO_INTROSPECTION_SECRET", TokenTypeHint: "access_token",
			Cache: CacheConfig{TTLSeconds: 60, MaxEntries: 1},
		},
	}
	setTestPolicy(t, &cfg, "listItems",
		`claims.sub == "alice" && userinfo.team == "trusted" && introspection.active == true && introspection.scope == "items:read"`)
	cfg.Policy.Routes[0].Auth.RequiredScopes = []string{"items:read"}
	proxy := startTestProxy(t, cfg)

	withoutScope := issuer.sign(t, nil)
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", withoutScope, "")
	status, body, headers := sendRequest(t, req)
	if status != http.StatusForbidden || headers.Get("X-Proxy-Outcome") != string(outcomeInsufficientScope) {
		t.Fatalf("missing incoming scope: HTTP %d: %s", status, body)
	}
	bob := issuer.sign(t, map[string]any{"sub": "bob", "scope": "items:read"})
	req = authedRequest(t, http.MethodGet, proxy.URL+"/items", bob, "")
	status, body, _ = sendRequest(t, req)
	if status != http.StatusForbidden {
		t.Fatalf("cheap CEL false branch: HTTP %d: %s", status, body)
	}
	if userinfoCalls.Load() != 0 || introspectionCalls.Load() != 0 {
		t.Fatal("lookups occurred despite scope/CEL short circuit")
	}
	first := issuer.sign(t, map[string]any{"scope": "items:read", "jti": "first"})
	second := issuer.sign(t, map[string]any{"scope": "items:read", "jti": "second"})
	for _, token := range []string{first, first, second, first} {
		req = authedRequest(t, http.MethodGet, proxy.URL+"/items", token, "")
		status, body, _ = sendRequest(t, req)
		if status != http.StatusNoContent {
			t.Fatalf("identity lookup: HTTP %d: %s", status, body)
		}
	}
	if userinfoCalls.Load() != 3 || introspectionCalls.Load() != 3 || forwarded.Load() != 4 {
		t.Fatalf("identity cache reuse/eviction: userinfo=%d introspection=%d upstream=%d",
			userinfoCalls.Load(), introspectionCalls.Load(), forwarded.Load())
	}
	req = authedRequest(t, http.MethodGet, proxy.URL+"/items/any", first, "")
	status, body, _ = sendRequest(t, req)
	if status != http.StatusNoContent || userinfoCalls.Load() != 3 || introspectionCalls.Load() != 3 {
		t.Fatalf("unrelated route triggered identity lookup: HTTP %d: %s", status, body)
	}
}

func TestIdentityLookupFailuresFailClosed(t *testing.T) {
	issuer := newTestIssuer(t)
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("SEKISHO_INTROSPECTION_FAILURE_SECRET", "secret")
	tests := []struct {
		name, source, body, contentType string
		dependencyStatus                int
		wantStatus                      int
		wantCode                        outcomeCode
	}{
		{"userinfo subject mismatch", "userinfo", `{"sub":"mallory"}`, "application/json", 0, 401, outcomeUserinfoMismatch},
		{"userinfo malformed", "userinfo", `{"sub":"alice","sub":"mallory"}`, "application/json", 0, 502, outcomeUserinfoInvalid},
		{"any cannot hide userinfo failure", "userinfo_any", `{"sub":"alice","sub":"mallory"}`, "application/json", 0, 502, outcomeUserinfoInvalid},
		{"userinfo oversized", "userinfo", strings.Repeat("x", maxIdentityResponseBytes+1), "application/json", 0, 502, outcomeUserinfoInvalid},
		{"userinfo media type", "userinfo", `{"sub":"alice"}`, "application/json-bad", 0, 502, outcomeUserinfoInvalid},
		{"userinfo rejected", "userinfo", strings.Repeat("x", maxIdentityResponseBytes+1), "application/json", 503, 502, outcomeUserinfoUnavailable},
		{"introspection inactive", "introspection", `{"active":false}`, "application/json", 0, 401, outcomeTokenInactive},
		{"introspection wrong subject", "introspection", `{"active":true,"sub":"mallory"}`, "application/json", 0, 401, outcomeIntrospectionMismatch},
		{"introspection invalid active", "introspection", `{"active":"true"}`, "application/json", 0, 502, outcomeIntrospectionInvalid},
		{"introspection oversized", "introspection", strings.Repeat("x", maxIdentityResponseBytes+1), "application/json", 0, 502, outcomeIntrospectionInvalid},
		{"introspection expired", "introspection", `{"active":true,"exp":1}`, "application/json", 0, 401, outcomeTokenInactive},
		{"introspection rejected", "introspection", `{"active":true}`, "application/json", 403, 502, outcomeIntrospectionUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				if tc.dependencyStatus != 0 {
					w.WriteHeader(tc.dependencyStatus)
				}
				fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(endpoint.Close)
			cfg := testConfig(t, issuer, upstream.URL)
			if strings.HasPrefix(tc.source, "userinfo") {
				cfg.Identity.Userinfo = &UserinfoConfig{URL: endpoint.URL}
				if tc.source == "userinfo_any" {
					cfg.Policy.Routes[0].Check = &PolicyRule{Any: []PolicyRule{
						{CEL: `userinfo.sub == "alice"`}, {CEL: "true"},
					}}
				} else {
					setTestPolicy(t, &cfg, "listItems", `userinfo.sub == "alice" || claims.sub == "alice"`)
				}
			} else {
				cfg.Identity.Introspection = &IntrospectionConfig{
					URL: endpoint.URL, ClientID: "inspector", ClientAuth: "client_secret_basic",
					ClientSecretEnv: "SEKISHO_INTROSPECTION_FAILURE_SECRET",
				}
				setTestPolicy(t, &cfg, "listItems", `introspection.active == true || claims.sub == "alice"`)
			}
			handler, err := newProxy(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			var audit bytes.Buffer
			handler.auditLogger = slog.New(slog.NewJSONHandler(&audit, nil))
			proxy := httptest.NewServer(handler)
			t.Cleanup(proxy.Close)
			req := authedRequest(t, http.MethodGet, proxy.URL+"/items", issuer.sign(t, nil), "")
			status, body, headers := sendRequest(t, req)
			if status != tc.wantStatus || headers.Get("X-Proxy-Outcome") != string(tc.wantCode) {
				t.Fatalf("identity failure: HTTP %d (%s), want %d (%s): %s",
					status, headers.Get("X-Proxy-Outcome"), tc.wantStatus, tc.wantCode, body)
			}
			if tc.dependencyStatus != 0 &&
				!strings.Contains(audit.String(), fmt.Sprintf(`"dependency_status":%d`, tc.dependencyStatus)) {
				t.Fatalf("audit missing identity dependency status: %s", audit.String())
			}
			if strings.Contains(body, tc.body) && tc.dependencyStatus == 0 {
				t.Fatalf("identity error leaked endpoint response: %s", body)
			}
		})
	}
	if forwarded.Load() != 0 {
		t.Fatalf("%d failed identity checks reached the upstream", forwarded.Load())
	}
}

func TestUnusedIdentityEndpointDoesNotLoadCredentials(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("SEKISHO_UNUSED_IDENTITY_SECRET", "")
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.Identity = IdentityConfig{
		Userinfo: &UserinfoConfig{URL: "http://127.0.0.1:1/userinfo"},
		Introspection: &IntrospectionConfig{
			URL: "http://127.0.0.1:1/introspect", ClientID: "unused",
			ClientAuth: "client_secret_basic", ClientSecretEnv: "SEKISHO_UNUSED_IDENTITY_SECRET",
		},
	}
	proxy := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", issuer.sign(t, nil), "")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusNoContent {
		t.Fatalf("unused identity source blocked a request: HTTP %d: %s", status, body)
	}
}

func TestIntrospectionCacheExpiresWithResponse(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("SEKISHO_EXPIRY_TEST_SECRET", "test-secret")
	var calls atomic.Int32
	var responseExpiry atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			expiry := time.Now().Add(1500 * time.Millisecond).Unix()
			responseExpiry.Store(expiry)
			fmt.Fprintf(w, `{"active":true,"sub":"alice","exp":%d}`, expiry)
			return
		}
		fmt.Fprint(w, `{"active":false}`)
	}))
	t.Cleanup(endpoint.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.Identity.Introspection = &IntrospectionConfig{
		URL: endpoint.URL, ClientID: "inspector", ClientAuth: "client_secret_basic",
		ClientSecretEnv: "SEKISHO_EXPIRY_TEST_SECRET",
		Cache:           CacheConfig{TTLSeconds: 60, MaxEntries: 4},
	}
	setTestPolicy(t, &cfg, "listItems", `introspection.active == true`)
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", token, "")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusNoContent {
		t.Fatalf("initial introspection: HTTP %d: %s", status, body)
	}
	time.Sleep(time.Until(time.Unix(responseExpiry.Load(), 0).Add(20 * time.Millisecond)))
	req = authedRequest(t, http.MethodGet, proxy.URL+"/items", token, "")
	status, body, headers := sendRequest(t, req)
	if status != http.StatusUnauthorized || headers.Get("X-Proxy-Outcome") != string(outcomeTokenInactive) ||
		calls.Load() != 2 {
		t.Fatalf("cached token remained active past introspection exp: HTTP %d, calls=%d: %s",
			status, calls.Load(), body)
	}
}

func TestConcurrentIdentityLookupCoalesces(t *testing.T) {
	issuer := newTestIssuer(t)
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sub":"alice"}`)
	}))
	t.Cleanup(userinfo.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.Identity.Userinfo = &UserinfoConfig{URL: userinfo.URL, Cache: CacheConfig{TTLSeconds: 30}}
	setTestPolicy(t, &cfg, "listItems", `userinfo.sub == "alice"`)
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)
	var wait sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			req, err := http.NewRequest(http.MethodGet, proxy.URL+"/items", nil)
			if err != nil {
				errs <- err
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				errs <- fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}()
	}
	deadline := time.After(5 * time.Second)
	for requests.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("no userinfo request observed")
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(release)
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("concurrent requests made %d userinfo calls, want one", requests.Load())
	}
}
