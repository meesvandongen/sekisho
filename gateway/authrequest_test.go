package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authRequestConfig(t *testing.T, issuer *testIssuer) Config {
	t.Helper()
	cfg := testConfig(t, issuer, "")
	cfg.Mode = "auth_request"
	return cfg
}

// subrequest builds what nginx sends for
//
//	proxy_set_header X-Original-Method $request_method;
//	proxy_set_header X-Original-URI $request_uri;
//
// against an internal location: a GET with no body to the auth endpoint.
func subrequest(t *testing.T, server, method, uri, token string) *http.Request {
	t.Helper()
	req := authedRequest(t, http.MethodGet, server+"/_sekisho/auth", token, "")
	req.Header.Set("X-Original-Method", method)
	req.Header.Set("X-Original-URI", uri)
	return req
}

func TestAuthRequestDecisions(t *testing.T) {
	issuer := newTestIssuer(t)
	t.Setenv("SEKISHO_AUTH_REQUEST_SECRET", "test-secret")
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":120}`,
			r.PostForm.Get("scope")+"-backend-token")
	}))
	t.Cleanup(tokenEndpoint.Close)

	cfg := authRequestConfig(t, issuer)
	cfg.BackendAuthProfiles = map[string]BackendAuthConfig{
		"write": {
			GrantType: "client_credentials", TokenURL: tokenEndpoint.URL, ClientID: "client",
			ClientAuth: "client_secret_basic", ClientSecretEnv: "SEKISHO_AUTH_REQUEST_SECRET",
			Scope: []string{"items:write"},
		},
	}
	setTestPolicy(t, &cfg, "listItems", `query.tenant == ["blue"] && !("x-original-uri" in headers)`)
	cfg.Policy.Routes[1].Auth = RouteAuthConfig{Backend: "write", RequiredScopes: []string{"items:write"}}
	cfg.Policy.Routes[2].Auth = RouteAuthConfig{Backend: "forward"}
	setTestPolicy(t, &cfg, "getItem", `method == "GET" && path_params.id == "7" && path == "/items/7"`)
	server := startTestProxy(t, cfg)

	token := issuer.sign(t, nil)
	writer := issuer.sign(t, map[string]any{"scope": "items:write"})
	tests := []struct {
		name, method, uri, token string
		status                   int
		decision, outcome, auth  string
	}{
		{"allowed without backend credential", "GET", "/items?tenant=blue", token, 200, "200", "allowed", ""},
		{"policy denial", "GET", "/items?tenant=red", token, 403, "403", "policy_denied", ""},
		{"backend profile", "POST", "/items", writer, 200, "200", "allowed", "Bearer items:write-backend-token"},
		{"missing scope", "POST", "/items", token, 403, "403", "insufficient_scope", ""},
		{"forwarded caller token", "GET", "/items/7", token, 200, "200", "allowed", "Bearer " + token},
		{"missing token", "GET", "/items/7", "", 401, "401", "auth_missing", ""},
		{"unknown route maps to 403", "GET", "/nope", token, 403, "404", "route_not_found", ""},
		{"wrong method maps to 403", "DELETE", "/items", token, 403, "405", "method_not_allowed", ""},
		{"ambiguous path", "GET", "/items/%2e%2e/7", token, 403, "400", "ambiguous_path", ""},
		{"absolute URI", "GET", "http://evil.example/items", token, 403, "400", "auth_request_invalid", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, _, headers := sendRequest(t, subrequest(t, server.URL, test.method, test.uri, test.token))
			if status != test.status || headers.Get("X-Sekisho-Status") != test.decision ||
				headers.Get("X-Proxy-Outcome") != test.outcome {
				t.Fatalf("got %d (decision %s, %s), want %d (decision %s, %s)", status,
					headers.Get("X-Sekisho-Status"), headers.Get("X-Proxy-Outcome"),
					test.status, test.decision, test.outcome)
			}
			if got := headers.Get("X-Sekisho-Authorization"); got != test.auth {
				t.Fatalf("X-Sekisho-Authorization = %q, want %q", got, test.auth)
			}
			if _, present := headers["X-Sekisho-Authorization"]; present != (test.status == 200) {
				t.Fatalf("X-Sekisho-Authorization present = %v on status %d", present, status)
			}
			if headers.Get("Cache-Control") != "no-store" {
				t.Fatalf("decision must not be cacheable: %v", headers)
			}
			if status == 401 && headers.Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("401 must carry WWW-Authenticate for nginx to pass on")
			}
		})
	}

	t.Run("missing original headers fail loudly", func(t *testing.T) {
		req := authedRequest(t, http.MethodGet, server.URL+"/items", token, "")
		status, _, headers := sendRequest(t, req)
		if status != 500 || headers.Get("X-Proxy-Outcome") != "auth_request_invalid" {
			t.Fatalf("got %d %s", status, headers.Get("X-Proxy-Outcome"))
		}
	})
	t.Run("subrequest body is ignored", func(t *testing.T) {
		req := authedRequest(t, http.MethodPost, server.URL+"/", token, strings.Repeat("x", 2<<20))
		req.Header.Set("X-Original-Method", "GET")
		req.Header.Set("X-Original-URI", "/items/7")
		if status, _, headers := sendRequest(t, req); status != 200 {
			t.Fatalf("got %d %s", status, headers.Get("X-Proxy-Outcome"))
		}
	})
}

func TestAuthRequestCustomHeaders(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := authRequestConfig(t, issuer)
	cfg.AuthRequest = AuthRequestConfig{MethodHeader: "X-Forwarded-Method", URIHeader: "X-Forwarded-Uri"}
	server := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodGet, server.URL+"/", issuer.sign(t, nil), "")
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Uri", "/items")
	if status, _, headers := sendRequest(t, req); status != 200 {
		t.Fatalf("got %d %s", status, headers.Get("X-Proxy-Outcome"))
	}
}

func TestAuthRequestConfiguration(t *testing.T) {
	issuer := newTestIssuer(t)
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"upstream not allowed", func(c *Config) { c.UpstreamURL = "https://api.example" }, "upstream_url is not used"},
		{"body policies rejected", func(c *Config) { c.Policy.Routes[1].Check = &PolicyRule{CEL: "body.amount < 5"} },
			"cannot use body"},
		{"raw body policies rejected", func(c *Config) { c.Policy.Routes[1].Check = &PolicyRule{CEL: "size(body_text) < 5"} },
			"cannot use body_text"},
		{"invalid header", func(c *Config) { c.AuthRequest.URIHeader = "X Original" }, "header name"},
		{"same header", func(c *Config) { c.AuthRequest = AuthRequestConfig{MethodHeader: "X-A", URIHeader: "x-a"} },
			"must differ"},
		{"unknown mode", func(c *Config) { c.Mode = "sidecar" }, "mode must be"},
		{"settings without mode", func(c *Config) {
			c.Mode = ""
			c.UpstreamURL = "https://api.example"
			c.AuthRequest.URIHeader = "X-Uri"
		}, `requires mode "auth_request"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := authRequestConfig(t, issuer)
			test.mutate(&cfg)
			_, err := newProxy(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}
