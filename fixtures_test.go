package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflinePolicyFixtures(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("examples", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	if err := runPolicyFixtures(context.Background(), cfg, "policy-tests.json", &result); err != nil {
		t.Fatal(err)
	}
	var lines []fixtureResult
	for _, line := range bytes.Split(bytes.TrimSpace(result.Bytes()), []byte{'\n'}) {
		var actual fixtureResult
		if err := json.Unmarshal(line, &actual); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, actual)
		if !actual.Passed {
			t.Fatalf("example policy fixture failed: %+v", actual)
		}
	}
	if len(lines) != 5 || lines[1].BackendAuth != "write" ||
		lines[2].Code != "package_denied" || lines[3].Code != string(outcomeInsufficientScope) {
		t.Fatalf("example fixtures did not cover allow, deny, and backend selection: %+v", lines)
	}
}

func TestOfflineFixturesNeverCallIdentityEndpoints(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:1")
	cfg.Identity = IdentityConfig{
		Userinfo: &UserinfoConfig{URL: "http://127.0.0.1:1/userinfo"},
		Introspection: &IntrospectionConfig{
			URL: "http://127.0.0.1:1/introspect", ClientID: "client",
			ClientAuth: "client_secret_basic", ClientSecretEnv: "MISSING_SECRET",
		},
	}
	setTestPolicy(t, &cfg, "listItems",
		`claims.sub == "alice" && userinfo.team == "trusted" && introspection.active == true`)
	cfg.Policy.Routes[0].Auth.RequiredScopes = []string{"read"}
	setTestPolicy(t, &cfg, "createItem", `size(body_bytes) == 2`)
	setTestPolicy(t, &cfg, "getItem", `host == "proxy.example" && path_params.id == "abc"`)
	data := `[
		{
			"name":"offline_allow", "method":"GET", "path":"/items",
			"claims":{"sub":"alice","scope":"read"},
			"userinfo":{"sub":"alice","team":"trusted"},
			"introspection":{"active":true,"sub":"alice"},
			"expected":{"allowed":true,"backend_auth":"none"}
		},
		{
			"name":"offline_inactive", "method":"GET", "path":"/items",
			"claims":{"sub":"alice","scope":"read"},
			"userinfo":{"sub":"alice","team":"trusted"},
			"introspection":{"active":false},
			"expected":{"allowed":false,"status":401,"code":"token_inactive"}
		},
		{
			"name":"missing_fixture", "method":"GET", "path":"/items",
			"claims":{"sub":"alice","scope":"read"},
			"userinfo":{"sub":"alice","team":"trusted"},
			"expected":{"allowed":false,"status":403,"code":"policy_error"}
		},
		{
			"name":"binary_body", "method":"POST", "path":"/items",
			"body_base64":"AP8=",
			"expected":{"allowed":true,"backend_auth":"none"}
		},
		{
			"name":"custom_host", "method":"GET", "path":"/items/abc",
			"host":"proxy.example",
			"expected":{"allowed":true,"backend_auth":"none"}
		}
	]`
	path := filepath.Join(t.TempDir(), "fixtures.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runPolicyFixtures(context.Background(), cfg, path, &output); err != nil {
		t.Fatalf("fixtures contacted a remote endpoint or failed: %v\n%s", err, output.String())
	}
	if got := strings.Count(output.String(), `"passed":true`); got != 5 {
		t.Fatalf("not all offline fixtures passed: %s", output.String())
	}
}

func TestFixtureMismatchAndMalformedInput(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := testConfig(t, issuer, "http://127.0.0.1:8081")
	path := filepath.Join(t.TempDir(), "fixtures.json")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`[{"name":"wrong","method":"GET","path":"/items","expected":{"allowed":false,"status":403,"code":"policy_denied"}}]`)
	var output bytes.Buffer
	if err := runPolicyFixtures(context.Background(), cfg, path, &output); err == nil ||
		!strings.Contains(err.Error(), "1 policy fixture(s) failed") ||
		!strings.Contains(output.String(), `"passed":false`) {
		t.Fatalf("mismatch did not fail clearly: %v, %s", err, output.String())
	}
	for _, tc := range []struct {
		name, input, want string
	}{
		{"duplicate keys", `[{"name":"a","name":"b"}]`, "duplicate JSON object key"},
		{"unknown fields", `[{"name":"case","method":"GET","path":"/items","unsafe":true}]`, "unknown field"},
		{"missing expectation", `[{"name":"case","method":"GET","path":"/items"}]`, "expected.allowed is required"},
		{"oversized file", strings.Repeat("x", maxFixtureBytes+1), "exceed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(tc.input)
			if err := runPolicyFixtures(context.Background(), cfg, path, &bytes.Buffer{}); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed fixture accepted: %v", err)
			}
		})
	}
}
