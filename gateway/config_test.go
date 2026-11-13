package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidProxyConfigurationFailsClosed(t *testing.T) {
	issuer := newTestIssuer(t)
	t.Setenv("SEKISHO_MISSING_SECRET_TEST", "")
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid configuration must not start a proxy")
	}))
	t.Cleanup(upstream.Close)
	tests := []struct {
		name, want string
		change     func(*Config)
	}{
		{
			name: "unconfigured algorithm", want: "unsupported oidc algorithm",
			change: func(c *Config) { c.OIDC.Algorithms = []string{"none"} },
		},
		{
			name: "unknown policy operation", want: "unknown operationId",
			change: func(c *Config) {
				c.Policy.Routes = append(c.Policy.Routes, RoutePolicyConfig{
					Match: PolicySelector{OperationID: "typo"},
					Check: PolicyRule{CEL: "true"},
					Auth:  RouteAuthConfig{Backend: "none"},
				})
			},
		},
		{
			name: "non-boolean policy", want: "must return a boolean",
			change: func(c *Config) { setTestPolicy(t, c, "listItems", "1 + 1") },
		},
		{
			name: "orphan credentials", want: "require a grant_type",
			change: func(c *Config) { c.BackendAuth.ClientSecretEnv = "UNUSED_SECRET" },
		},
		{
			name: "missing secret", want: "environment variable",
			change: func(c *Config) {
				c.BackendAuth = BackendAuthConfig{
					GrantType: "client_credentials", TokenURL: issuer.server.URL + "/token",
					ClientID: "client", ClientAuth: "client_secret_basic",
					ClientSecretEnv: "SEKISHO_MISSING_SECRET_TEST",
				}
				c.Policy.Routes[0].Auth.Backend = "default"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, issuer, upstream.URL)
			tc.change(&cfg)
			_, err := newProxy(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newProxy error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestExampleConfigurationIsRunnable(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := newTestIssuer(t)
	upstream, received := backendRecorder(t)
	cfg.OIDC.Issuer = issuer.server.URL
	cfg.OIDC.JWKSURI = issuer.server.URL + "/jwks"
	cfg.UpstreamURL = upstream.URL + "/base"
	cfg.BackendAuth = BackendAuthConfig{}
	for index := range cfg.Policy.Routes {
		cfg.Policy.Routes[index].Auth.Backend = "none"
	}
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, map[string]any{
		"aud": cfg.OIDC.Audience, "scope": "items:read items:write",
	})
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/items", ""},
		{http.MethodPost, "/items?tenant=blue", `{"amount":3}`},
	} {
		req := authedRequest(t, tc.method, proxy.URL+tc.path, token, tc.body)
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		status, body, _ := sendRequest(t, req)
		if status != http.StatusNoContent {
			t.Fatalf("example %s %s: HTTP %d: %s", tc.method, tc.path, status, body)
		}
		if got := <-received; got != "" {
			t.Fatalf("example forwarded inbound bearer token: %q", got)
		}
	}
}

func TestConfigFileIsStrictAndRelativeToItsDirectory(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(specPath, []byte(testOpenAPI), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	data := `{"openapi_file":"api.yaml","upstream_url":"http://127.0.0.1:8081","oidc":{"issuer":"https://issuer.example","audience":"proxy"}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OpenAPIFile != specPath || cfg.MaxBodyBytes != defaultBodyBytes {
		t.Fatalf("relative spec or defaults not applied: %+v", cfg)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(data, "}")+`,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown config field was accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(data, "}")+
		`,"oidc":{"issuer":"https://other.invalid","audience":"proxy"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate config field was accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(data, "}")+
		`,"policy":{"default":"true"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), `unknown field "default"`) {
		t.Fatalf("legacy permissive policy config was accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(data, "}")+`,"otel":{"enabled":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), `unknown field "otel"`) {
		t.Fatalf("legacy OTel config was silently accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(data+" {}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("multiple JSON documents were accepted")
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%s%s", data, strings.Repeat(" ", maxConfigBytes))), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized config was accepted: %v", err)
	}
}

func TestExternalOpenAPIReferencesAreRejected(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	spec := `openapi: 3.0.3
info: { title: external, version: "1" }
paths:
  /items:
    get:
      responses:
        "200":
          $ref: "https://untrusted.example/response.yaml"
`
	if err := os.WriteFile(cfg.OpenAPIFile, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := newProxy(context.Background(), cfg); err == nil {
		t.Fatal("external OpenAPI reference was accepted")
	}
}

func TestOpenAPISpecSizeLimitAndLocalReferences(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	spec := `openapi: 3.0.3
info: { title: local, version: "1" }
components:
  responses:
    Ok:
      description: ok
paths:
  /items:
    get:
      operationId: listItems
      responses:
        "200":
          $ref: "#/components/responses/Ok"
`
	if err := os.WriteFile(cfg.OpenAPIFile, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.Routes = cfg.Policy.Routes[:1]
	if _, err := newProxy(context.Background(), cfg); err != nil {
		t.Fatalf("local OpenAPI reference no longer works: %v", err)
	}
	if err := os.WriteFile(cfg.OpenAPIFile, []byte(strings.Repeat("x", maxOpenAPIBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newProxy(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized OpenAPI spec accepted: %v", err)
	}
}
