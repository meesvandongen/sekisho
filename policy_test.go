package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPolicyCoverageAndSelectors(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	tests := []struct {
		name, want string
		change     func(*Config)
	}{
		{"missing all bindings", "missing policy bindings", func(c *Config) { c.Policy = PolicyConfig{} }},
		{"uncovered operation", "GET /items/{id}", func(c *Config) { c.Policy.Routes = c.Policy.Routes[:2] }},
		{"duplicate binding", "multiple policy bindings", func(c *Config) {
			c.Policy.Routes = append(c.Policy.Routes, RoutePolicyConfig{
				Match: PolicySelector{Path: "/items", Method: http.MethodGet},
				Check: PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{Backend: "none"},
			})
		}},
		{"unknown path", "unknown OpenAPI path/method", func(c *Config) {
			c.Policy.Routes[0].Match = PolicySelector{Path: "/missing", Method: http.MethodGet}
		}},
		{"ambiguous selector", "not both", func(c *Config) {
			c.Policy.Routes[0].Match.Path = "/items"
		}},
		{"missing backend selection", "backend must explicitly select", func(c *Config) {
			c.Policy.Routes[0].Auth.Backend = ""
		}},
		{"default backend absent", "backend default is not configured", func(c *Config) {
			c.Policy.Routes[0].Auth.Backend = "default"
		}},
		{"unknown backend", "unknown backend auth profile", func(c *Config) {
			c.Policy.Routes[0].Auth.Backend = "missing"
		}},
		{"invalid scope", "invalid or duplicate required scope", func(c *Config) {
			c.Policy.Routes[0].Auth.RequiredScopes = []string{"read item"}
		}},
		{"unknown reference", "unknown policy reference", func(c *Config) {
			c.Policy.Routes[0].Check = PolicyRule{Ref: "missing"}
		}},
		{"cyclic definitions", "cycle in policy reference", func(c *Config) {
			c.Policy.Definitions = map[string]PolicyRule{"a": {Ref: "b"}, "b": {Ref: "a"}}
		}},
		{"expanding references", "evaluation exceeds depth or node limit", func(c *Config) {
			c.Policy.Definitions = map[string]PolicyRule{"level_0": {CEL: "true"}}
			for depth := 1; depth <= 9; depth++ {
				previous := fmt.Sprintf("level_%d", depth-1)
				c.Policy.Definitions[fmt.Sprintf("level_%d", depth)] =
					PolicyRule{All: []PolicyRule{{Ref: previous}, {Ref: previous}}}
			}
			c.Policy.Routes[0].Check = PolicyRule{Ref: "level_9"}
		}},
		{"empty composition", "requires at least one child", func(c *Config) {
			c.Policy.Routes[0].Check = PolicyRule{All: []PolicyRule{}}
		}},
		{"ambiguous rule", "exactly one", func(c *Config) {
			c.Policy.Routes[0].Check = PolicyRule{CEL: "true", Ref: "unknown"}
		}},
		{"file missing", "open policy file", func(c *Config) {
			c.Policy.Routes[0].Check = PolicyRule{File: filepath.Join(t.TempDir(), "missing.cel")}
		}},
		{"userinfo unconfigured", "unconfigured userinfo", func(c *Config) {
			setTestPolicy(t, c, "listItems", `userinfo.sub == "alice"`)
		}},
		{"introspection unconfigured", "unconfigured introspection", func(c *Config) {
			setTestPolicy(t, c, "listItems", `introspection.active == true`)
		}},
		{"invalid deny status", "response.status must be", func(c *Config) {
			c.Policy.Routes[0].OnDeny.Response.Status = 200
		}},
		{"false success code", "cannot report a denied request as forwarded", func(c *Config) {
			c.Policy.Routes[0].OnDeny.Response.Code = "forwarded"
		}},
		{"unsafe deny detail", "without newlines", func(c *Config) {
			c.Policy.Routes[0].OnDeny.Response.Detail = "secret\ninjected"
		}},
		{"unsafe audit message", "log.message must be", func(c *Config) {
			c.Policy.Routes[0].OnDeny.Log.Message = "no\nnewlines"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			selected := cfg
			selected.Policy = PolicyConfig{
				Definitions: make(map[string]PolicyRule),
				Routes:      append([]RoutePolicyConfig(nil), cfg.Policy.Routes...),
			}
			tc.change(&selected)
			_, err := newProxy(context.Background(), selected)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newProxy error = %v; want %q", err, tc.want)
			}
		})
	}
}

func TestOperationObjectWithoutOperationID(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	spec := `openapi: 3.0.3
info: { title: operations, version: "1" }
paths:
  /deliveries/{id}:
    post:
      tags: [publish, artifacts]
      summary: publish a delivery
      parameters:
        - in: path
          name: id
          required: true
          schema: { type: string }
      responses:
        "204": { description: accepted }
`
	if err := os.WriteFile(cfg.OpenAPIFile, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.Routes = []RoutePolicyConfig{{
		Match: PolicySelector{Path: "/deliveries/{id}", Method: http.MethodPost},
		Check: PolicyRule{CEL: `operation.tags == ["publish", "artifacts"] &&
			operation.summary == "publish a delivery" && operation.responses["204"].description == "accepted" &&
			!has(operation.operationId) && operation_id == "" && path_params.id == "abc"`},
		Auth: RouteAuthConfig{Backend: "none"},
	}}
	proxy := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodPost, proxy.URL+"/deliveries/abc", issuer.sign(t, nil), "")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusNoContent {
		t.Fatalf("policy did not see OpenAPI operation: HTTP %d: %s", status, body)
	}
}

func TestNamedCompositionFilesParamsAndShortCircuit(t *testing.T) {
	issuer := newTestIssuer(t)
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	file := filepath.Join(t.TempDir(), "limit.cel")
	if err := os.WriteFile(file, []byte(`body.amount <= params.max && operation.operationId == "createItem"`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.Definitions = map[string]PolicyRule{
		"subject": {CEL: `claims.sub == params.subject`},
		"amount":  {File: file},
		"publish": {All: []PolicyRule{
			{Ref: "subject", Params: map[string]any{"subject": "alice"}},
			{Any: []PolicyRule{
				{CEL: `query["bypass"][0] == "yes"`},
				{Ref: "amount", Params: map[string]any{"max": float64(5)}},
			}},
			{Not: &PolicyRule{CEL: `headers["x-block"][0] == "yes"`}},
		}},
	}
	for index := range cfg.Policy.Routes {
		if cfg.Policy.Routes[index].Match.OperationID == "createItem" {
			cfg.Policy.Routes[index].Check = PolicyRule{Ref: "publish"}
			cfg.Policy.Routes[index].Params = map[string]any{"subject": "nobody", "max": float64(0)}
		}
	}
	proxy := startTestProxy(t, cfg)
	token := issuer.sign(t, nil)
	for _, tc := range []struct {
		name, url, body, blocked string
		want                     int
	}{
		{"file limit", "/items?bypass=no", `{"amount":3}`, "no", 204},
		{"blocked", "/items?bypass=no", `{"amount":3}`, "yes", 403},
		{"over limit", "/items?bypass=no", `{"amount":6}`, "no", 403},
		{"short circuit", "/items?bypass=yes", "not JSON", "no", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := authedRequest(t, http.MethodPost, proxy.URL+tc.url, token, tc.body)
			req.Header.Set("X-Block", tc.blocked)
			req.Header.Set("Content-Type", "application/json")
			status, body, _ := sendRequest(t, req)
			if status != tc.want {
				t.Fatalf("HTTP %d, want %d: %s", status, tc.want, body)
			}
		})
	}
	if forwarded.Load() != 2 {
		t.Fatalf("expected two forwarded requests, got %d", forwarded.Load())
	}
}

type readCounter struct {
	reader io.Reader
	count  int
}

func (c *readCounter) Read(data []byte) (int, error) {
	c.count++
	return c.reader.Read(data)
}

func TestPolicySkipsUnusedBody(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	for index := range cfg.Policy.Routes {
		if cfg.Policy.Routes[index].Match.OperationID == "createItem" {
			cfg.Policy.Routes[index].Check = PolicyRule{All: []PolicyRule{
				{CEL: "false"}, {CEL: `body.allowed == true`},
			}}
		}
	}
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	reader := &readCounter{reader: strings.NewReader(`{"allowed":true}`)}
	req := httptest.NewRequest(http.MethodPost, "/items", io.NopCloser(reader))
	req.Header.Set("Authorization", "Bearer "+issuer.sign(t, nil))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || reader.count != 0 {
		t.Fatalf("short-circuited body was read: status=%d reads=%d", w.Code, reader.count)
	}
}

func TestCustomDenialResponseAndAudit(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	setTestPolicy(t, &cfg, "listItems", "false")
	cfg.Policy.Routes[0].Name = "publisher_guard"
	cfg.Policy.Routes[0].OnDeny = DenyConfig{
		Response: DenyResponseConfig{Status: http.StatusNotFound, Code: "publisher_hidden", Detail: "This operation is unavailable."},
		Log:      DenyLogConfig{Level: "warn", Reason: "publisher_not_allowed", Message: "publisher policy denied"},
	}
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	handler.auditLogger = slog.New(slog.NewJSONHandler(&audit, nil))
	req := httptest.NewRequest(http.MethodGet, "/items?password=sensitive", nil)
	req.Header.Set("Authorization", "Bearer "+issuer.sign(t, nil))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var problem struct {
		Code, Detail string
		Status       int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusNotFound || w.Header().Get("X-Proxy-Outcome") != "publisher_hidden" ||
		problem.Code != "publisher_hidden" || problem.Status != 404 ||
		problem.Detail != "This operation is unavailable." {
		t.Fatalf("unexpected custom denial: HTTP %d: %s", w.Code, w.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(audit.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["level"] != "WARN" || record["policy"] != "publisher_guard" ||
		record["reason"] != "publisher_not_allowed" || record["outcome"] != "publisher_hidden" ||
		record["msg"] != "publisher policy denied" ||
		strings.Contains(audit.String(), "sensitive") {
		t.Fatalf("unexpected audit record: %v", record)
	}
}

func TestPolicyFileSizeLimit(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	file := filepath.Join(t.TempDir(), "too-large.cel")
	if err := os.WriteFile(file, []byte(strings.Repeat("x", maxPolicyFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}

	cfg.Policy.Routes[0].Check = PolicyRule{File: file}
	if _, err := newProxy(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized policy file was accepted: %v", err)
	}
}

func TestUnusedOperationsAreNotMaterialized(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	spec := strings.Replace(testOpenAPI, "operationId: listItems",
		"operationId: listItems\n      summary: "+strings.Repeat("x", maxOperationBytes), 1)
	if err := os.WriteFile(cfg.OpenAPIFile, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newProxy(context.Background(), cfg); err != nil {
		t.Fatalf("unused operation metadata was parsed for CEL: %v", err)
	}
	setTestPolicy(t, &cfg, "listItems", `operation.summary != ""`)
	if _, err := newProxy(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "operation exceeds") {
		t.Fatalf("oversized referenced operation was accepted: %v", err)
	}
}
