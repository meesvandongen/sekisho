package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const compositionOpenAPI = `openapi: 3.0.3
info: { title: composition, version: "1" }
paths:
  /items:
    get:
      operationId: listItems
      tags: [items]
      responses: { "204": { description: ok } }
    post:
      operationId: createItem
      tags: [items, write]
      responses: { "204": { description: ok } }
  /admin/users:
    get:
      operationId: listUsers
      tags: [admin]
      x-tier: internal
      responses: { "204": { description: ok } }
  /admin/users/{id}:
    delete:
      operationId: deleteUser
      tags: [admin, write]
      x-tier: internal
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      responses: { "204": { description: ok } }
  /administrators:
    get:
      operationId: listAdministrators
      responses: { "204": { description: ok } }
`

func loadCompositionSpec(t *testing.T) *openapi3.T {
	t.Helper()
	spec, err := openapi3.NewLoader().LoadFromData([]byte(compositionOpenAPI))
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestMatcherJSON(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  PolicyMatcher
		err   string
	}{
		{`"*"`, PolicyMatcher{Wildcard: true}, ""},
		{`{"operation_id":"a"}`, PolicyMatcher{OperationID: stringList{"a"}}, ""},
		{`{"operation_id":["a","b"],"method":"GET"}`,
			PolicyMatcher{OperationID: stringList{"a", "b"}, Method: stringList{"GET"}}, ""},
		{`{"not":"*"}`, PolicyMatcher{Not: &PolicyMatcher{Wildcard: true}}, ""},
		{`{"any":[{"tag":"a"},"*"]}`,
			PolicyMatcher{Any: []PolicyMatcher{{Tag: stringList{"a"}}, {Wildcard: true}}}, ""},
		{`"all"`, PolicyMatcher{}, `must be "*"`},
		{`null`, PolicyMatcher{}, `must be "*" or an object`},
		{`{"operationId":"a"}`, PolicyMatcher{}, "unknown field"},
		{`{"tag":42}`, PolicyMatcher{}, "string or an array"},
	} {
		var got PolicyMatcher
		err := json.Unmarshal([]byte(tc.input), &got)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("%s: error = %v, want %q", tc.input, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.input, err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(tc.want)
		if got.Wildcard != tc.want.Wildcard || !bytes.Equal(gotJSON, wantJSON) {
			t.Fatalf("%s: decoded %+v, want %+v", tc.input, got, tc.want)
		}
	}
}

func TestMatcherSelection(t *testing.T) {
	index, _, err := indexOperations(loadCompositionSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	selected := func(matcher PolicyMatcher) []string {
		t.Helper()
		set, err := (&matcherCompiler{index: index}).selectOperations(matcher, 0)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for position, operation := range index.operations {
			if set.contains(position) {
				ids = append(ids, operation.id)
			}
		}
		slices.Sort(ids)
		return ids
	}
	for _, tc := range []struct {
		name    string
		matcher PolicyMatcher
		want    []string
	}{
		{"wildcard", PolicyMatcher{Wildcard: true},
			[]string{"createItem", "deleteUser", "listAdministrators", "listItems", "listUsers"}},
		{"operation list", PolicyMatcher{OperationID: stringList{"listItems", "deleteUser"}},
			[]string{"deleteUser", "listItems"}},
		{"lowercase method", PolicyMatcher{Method: stringList{"get"}},
			[]string{"listAdministrators", "listItems", "listUsers"}},
		{"segment prefix", PolicyMatcher{PathPrefix: stringList{"/admin"}}, []string{"deleteUser", "listUsers"}},
		{"trailing slash prefix", PolicyMatcher{PathPrefix: stringList{"/admin/users/"}},
			[]string{"deleteUser", "listUsers"}},
		{"keys are and-ed", PolicyMatcher{Tag: stringList{"write"}, PathPrefix: stringList{"/admin"}},
			[]string{"deleteUser"}},
		{"tag list is any-of", PolicyMatcher{Tag: stringList{"admin", "items"}},
			[]string{"createItem", "deleteUser", "listItems", "listUsers"}},
		{"extension", PolicyMatcher{Extension: map[string]any{"x-tier": "internal"}},
			[]string{"deleteUser", "listUsers"}},
		{"not", PolicyMatcher{Not: &PolicyMatcher{Tag: stringList{"admin", "items"}}},
			[]string{"listAdministrators"}},
		{"any", PolicyMatcher{Any: []PolicyMatcher{
			{OperationID: stringList{"listItems"}}, {Path: stringList{"/administrators"}},
		}}, []string{"listAdministrators", "listItems"}},
		{"all with exclusion", PolicyMatcher{All: []PolicyMatcher{
			{Tag: stringList{"admin"}}, {Not: &PolicyMatcher{Method: stringList{"GET"}}},
		}}, []string{"deleteUser"}},
	} {
		if got := selected(tc.matcher); !slices.Equal(got, tc.want) {
			t.Fatalf("%s: selected %v, want %v", tc.name, got, tc.want)
		}
	}
}

func compositionConfig(routes ...RoutePolicyConfig) Config {
	return Config{
		BackendAuth: BackendAuthConfig{GrantType: "none"},
		BackendAuthProfiles: map[string]BackendAuthConfig{
			"read": {GrantType: "client_credentials"}, "write": {GrantType: "client_credentials"},
			"admin": {GrantType: "client_credentials"},
		},
		Policy: PolicyConfig{Routes: routes},
	}
}

func TestBackendResolutionByNarrowestMatch(t *testing.T) {
	spec := loadCompositionSpec(t)
	check := &PolicyRule{CEL: "true"}
	backends := func(cfg Config) map[string]string {
		t.Helper()
		policies, err := compilePolicies(cfg, spec)
		if err != nil {
			t.Fatal(err)
		}
		result := make(map[string]string)
		for _, route := range policies.order {
			result[route.operationID] = route.backendName + "@" + route.backendBinding.label()
		}
		return result
	}
	got := backends(compositionConfig(
		RoutePolicyConfig{Name: "admin_area", Match: PolicyMatcher{Tag: stringList{"admin"}}, Auth: RouteAuthConfig{Backend: "admin"}},
		RoutePolicyConfig{Name: "baseline", Match: PolicyMatcher{Wildcard: true}, Check: check, Auth: RouteAuthConfig{Backend: "read"}},
		RoutePolicyConfig{Match: PolicyMatcher{OperationID: stringList{"deleteUser"}}, Auth: RouteAuthConfig{Backend: "write"}},
	))
	want := map[string]string{
		"listItems":          "read@routes[1] baseline",
		"listAdministrators": "read@routes[1] baseline",
		"createItem":         "read@routes[1] baseline",
		"listUsers":          "admin@routes[0] admin_area",
		"deleteUser":         "write@routes[2]",
	}
	for id, backend := range want {
		if got[id] != backend {
			t.Fatalf("%s resolved to %q, want %q (all: %v)", id, got[id], backend, got)
		}
	}

	// Overlapping bindings that are not nested may coexist when they agree.
	got = backends(compositionConfig(
		RoutePolicyConfig{Match: PolicyMatcher{Wildcard: true}, Check: check, Auth: RouteAuthConfig{Backend: "read"}},
		RoutePolicyConfig{Match: PolicyMatcher{Tag: stringList{"admin"}}, Auth: RouteAuthConfig{Backend: "admin"}},
		RoutePolicyConfig{Match: PolicyMatcher{Tag: stringList{"write"}}, Auth: RouteAuthConfig{Backend: "admin"}},
	))
	if !strings.HasPrefix(got["deleteUser"], "admin@") || !strings.HasPrefix(got["createItem"], "admin@") {
		t.Fatalf("agreeing overlaps did not resolve: %v", got)
	}

	// Overlapping bindings that disagree must be settled explicitly.
	conflict := compositionConfig(
		RoutePolicyConfig{Match: PolicyMatcher{Wildcard: true}, Check: check, Auth: RouteAuthConfig{Backend: "read"}},
		RoutePolicyConfig{Name: "admin_area", Match: PolicyMatcher{Tag: stringList{"admin"}}, Auth: RouteAuthConfig{Backend: "admin"}},
		RoutePolicyConfig{Name: "writes", Match: PolicyMatcher{Tag: stringList{"write"}}, Auth: RouteAuthConfig{Backend: "write"}},
	)
	_, err := compilePolicies(conflict, spec)
	if err == nil || !strings.Contains(err.Error(), "DELETE /admin/users/{id}") ||
		!strings.Contains(err.Error(), "routes[1] admin_area") || !strings.Contains(err.Error(), "routes[2] writes") ||
		strings.Contains(err.Error(), "POST /items") {
		t.Fatalf("conflict error = %v", err)
	}
	conflict.Policy.Routes = append(conflict.Policy.Routes, RoutePolicyConfig{
		Match: PolicyMatcher{OperationID: stringList{"deleteUser"}}, Auth: RouteAuthConfig{Backend: "admin"},
	})
	if got := backends(conflict); got["deleteUser"] != "admin@routes[3]" || got["createItem"] != "write@routes[2] writes" {
		t.Fatalf("narrower binding did not settle the conflict: %v", got)
	}
}

func TestExplainOutput(t *testing.T) {
	policies, err := compilePolicies(compositionConfig(
		RoutePolicyConfig{Name: "baseline", Match: PolicyMatcher{Wildcard: true},
			Check: &PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{Backend: "read"}},
		RoutePolicyConfig{Name: "admin_area", Match: PolicyMatcher{PathPrefix: stringList{"/admin"}},
			Check: &PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{Backend: "forward", RequiredScopes: []string{"admin"}}},
		RoutePolicyConfig{Match: PolicyMatcher{Method: stringList{"DELETE"}},
			Check: &PolicyRule{CEL: "true"}, Auth: RouteAuthConfig{RequiredScopes: []string{"admin", "delete"}}},
	), loadCompositionSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writePolicyExplanation(policies, &output); err != nil {
		t.Fatal(err)
	}
	want := `DELETE /admin/users/{id} (deleteUser)
  backend: forward from routes[1] admin_area
  scopes:  admin (routes[1] admin_area), delete (routes[2])
  checks:  routes[0] baseline → routes[1] admin_area → routes[2]
`
	if !strings.Contains(output.String(), want) ||
		!strings.Contains(output.String(), "GET /items (listItems)\n  backend: read from routes[0] baseline\n  checks:  routes[0] baseline\n") {
		t.Fatalf("unexpected explanation:\n%s", output.String())
	}
}

func TestStackedBindingsAndForwardBackend(t *testing.T) {
	issuer := newTestIssuer(t)
	received := make(chan string, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	if err := os.WriteFile(cfg.OpenAPIFile, []byte(compositionOpenAPI), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.Routes = []RoutePolicyConfig{
		{
			Name: "baseline", Match: PolicyMatcher{Wildcard: true},
			Check: &PolicyRule{CEL: `claims.sub == "alice"`}, Auth: RouteAuthConfig{Backend: "none"},
			OnDeny: DenyConfig{Response: DenyResponseConfig{Status: http.StatusUnauthorized, Code: "unknown_subject"}},
		},
		{
			Name: "admin_only", Match: PolicyMatcher{Tag: stringList{"admin"}},
			Check: &PolicyRule{CEL: `"role" in claims && claims.role == "admin"`},
			Auth:  RouteAuthConfig{Backend: "forward", RequiredScopes: []string{"admin"}},
			OnDeny: DenyConfig{
				Response: DenyResponseConfig{Status: http.StatusNotFound, Code: "hidden"},
				Log:      DenyLogConfig{Reason: "not_admin"},
			},
		},
		{
			Name: "confirm_delete", Match: PolicyMatcher{PathPrefix: stringList{"/admin"}, Method: stringList{"DELETE"}},
			Check: &PolicyRule{CEL: `"confirm" in query`},
		},
	}
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	handler.auditLogger = slog.New(slog.NewJSONHandler(&audit, nil))
	admin := map[string]any{"role": "admin", "scope": "admin"}
	for _, tc := range []struct {
		name, method, target string
		claims               map[string]any
		status               int
		outcome, policy      string
		forwardToken         bool
	}{
		{"baseline allows", "GET", "/items", nil, 204, "forwarded", "baseline", false},
		{"baseline denies first", "GET", "/admin/users", map[string]any{"sub": "bob", "role": "admin", "scope": "admin"},
			401, "unknown_subject", "baseline", false},
		{"admin forwards caller token", "GET", "/admin/users", admin, 204, "forwarded", "admin_only", true},
		{"admin check denies", "GET", "/admin/users", map[string]any{"scope": "admin"}, 404, "hidden", "admin_only", false},
		{"scopes before checks", "GET", "/admin/users", map[string]any{"sub": "bob"}, 403, "insufficient_scope", "admin_only", false},
		{"third binding denies", "DELETE", "/admin/users/1", admin, 403, "policy_denied", "confirm_delete", false},
		{"all bindings pass", "DELETE", "/admin/users/1?confirm=1", admin, 204, "forwarded", "admin_only", true},
		{"prefix is segment aware", "GET", "/administrators", nil, 204, "forwarded", "baseline", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit.Reset()
			token := issuer.sign(t, tc.claims)
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status || w.Header().Get("X-Proxy-Outcome") != tc.outcome {
				t.Fatalf("HTTP %d %s, want %d %s: %s", w.Code, w.Header().Get("X-Proxy-Outcome"),
					tc.status, tc.outcome, w.Body.String())
			}
			if tc.status == http.StatusNoContent {
				got := <-received
				want := ""
				if tc.forwardToken {
					want = "Bearer " + token
				}
				if got != want {
					t.Fatalf("upstream Authorization = %q, want %q", got, want)
				}
			}
			var record map[string]any
			if err := json.Unmarshal(audit.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["policy"] != tc.policy {
				t.Fatalf("audit policy = %v, want %s", record["policy"], tc.policy)
			}
		})
	}
	if len(received) != 0 {
		t.Fatalf("unexpected upstream requests: %d", len(received))
	}
}

func TestForwardIsReservedProfileName(t *testing.T) {
	cfg := testConfig(t, newTestIssuer(t), "http://127.0.0.1:1")
	cfg.BackendAuthProfiles = map[string]BackendAuthConfig{"forward": {GrantType: "client_credentials"}}
	if err := cfg.normalize(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("forward profile name was accepted: %v", err)
	}
}
