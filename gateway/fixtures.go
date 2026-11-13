package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/routers"
)

const (
	maxFixtureBytes = 1 << 20
	maxFixtureCases = 256
)

type policyFixture struct {
	Name          string              `json:"name"`
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	Host          string              `json:"host"`
	Headers       map[string][]string `json:"headers"`
	ContentType   string              `json:"content_type"`
	Body          *string             `json:"body"`
	BodyBase64    string              `json:"body_base64"`
	Claims        map[string]any      `json:"claims"`
	Userinfo      map[string]any      `json:"userinfo"`
	Introspection map[string]any      `json:"introspection"`
	Expected      fixtureExpected     `json:"expected"`
}

type fixtureExpected struct {
	Allowed     *bool  `json:"allowed"`
	Status      int    `json:"status"`
	Code        string `json:"code"`
	BackendAuth string `json:"backend_auth"`
}

type fixtureResult struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	Allowed     bool   `json:"allowed"`
	Status      int    `json:"status,omitempty"`
	Code        string `json:"code,omitempty"`
	BackendAuth string `json:"backend_auth,omitempty"`
}

func runPolicyFixtures(ctx context.Context, cfg Config, filePath string, output io.Writer) error {
	if err := cfg.normalize(); err != nil {
		return err
	}
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(cfg.configDir, filePath)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open policy fixtures: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if err != nil {
		return fmt.Errorf("read policy fixtures: %w", err)
	}
	if len(data) > maxFixtureBytes {
		return fmt.Errorf("policy fixtures exceed %d bytes", maxFixtureBytes)
	}
	if _, err := decodePolicyJSON(data); err != nil {
		return fmt.Errorf("invalid policy fixtures: %w", err)
	}
	var fixtures []policyFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixtures); err != nil {
		return fmt.Errorf("decode policy fixtures: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("policy fixtures must contain exactly one JSON array")
	}
	if len(fixtures) == 0 || len(fixtures) > maxFixtureCases {
		return fmt.Errorf("policy fixtures require 1..%d cases", maxFixtureCases)
	}
	router, policies, err := newPolicyRouter(ctx, cfg)
	if err != nil {
		return err
	}
	results := json.NewEncoder(output)
	failures := 0
	for index, fixture := range fixtures {
		if err := fixture.validate(); err != nil {
			return fmt.Errorf("fixture %d: %w", index, err)
		}
		actual, err := evaluateFixture(ctx, cfg, router, policies, fixture)
		if err != nil {
			return fmt.Errorf("fixture %q: %w", fixture.Name, err)
		}
		actual.Passed = actual.Allowed == *fixture.Expected.Allowed &&
			actual.Status == fixture.Expected.Status && actual.Code == fixture.Expected.Code &&
			actual.BackendAuth == fixture.Expected.BackendAuth
		if !actual.Passed {
			failures++
		}
		if err := results.Encode(actual); err != nil {
			return fmt.Errorf("write fixture result: %w", err)
		}
	}
	if failures != 0 {
		return fmt.Errorf("%d policy fixture(s) failed", failures)
	}
	return nil
}

func (f policyFixture) validate() error {
	if f.Name == "" || len(f.Name) > 128 || f.Method == "" || f.Path == "" {
		return fmt.Errorf("name, method and path are required")
	}
	if len(f.Host) > 255 || strings.ContainsAny(f.Host, " \t\r\n") {
		return fmt.Errorf("host must be at most 255 bytes without whitespace")
	}
	if f.Body != nil && f.BodyBase64 != "" {
		return fmt.Errorf("body and body_base64 cannot both be provided")
	}
	if f.Expected.Allowed == nil {
		return fmt.Errorf("expected.allowed is required")
	}
	if *f.Expected.Allowed {
		if f.Expected.Status != 0 || f.Expected.Code != "" || f.Expected.BackendAuth == "" {
			return fmt.Errorf("allowed fixtures require backend_auth and no status/code")
		}
	} else if f.Expected.Status == 0 || f.Expected.Code == "" || f.Expected.BackendAuth != "" {
		return fmt.Errorf("denied fixtures require status/code and no backend_auth")
	}
	return nil
}

func evaluateFixture(
	ctx context.Context, cfg Config, router routers.Router, policies *policySet, fixture policyFixture,
) (fixtureResult, error) {
	actual := fixtureResult{Name: fixture.Name}
	var body []byte
	if fixture.Body != nil {
		body = []byte(*fixture.Body)
	} else if fixture.BodyBase64 != "" {
		var err error
		body, err = base64.StdEncoding.DecodeString(fixture.BodyBase64)
		if err != nil {
			return actual, fmt.Errorf("body_base64: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, fixture.Method, "http://fixture.invalid"+fixture.Path, bytes.NewReader(body))
	if err != nil {
		return actual, fmt.Errorf("create fixture request: %w", err)
	}
	if fixture.Host != "" {
		req.Host = fixture.Host
	}
	for name, values := range fixture.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if fixture.ContentType != "" {
		req.Header.Set("Content-Type", fixture.ContentType)
	}
	if int64(len(body)) > cfg.MaxBodyBytes {
		return fixtureDenied(actual, http.StatusRequestEntityTooLarge, outcomeBodyTooLarge), nil
	}
	if ambiguousPath(req.URL) {
		return fixtureDenied(actual, http.StatusBadRequest, outcomeAmbiguousPath), nil
	}
	route, pathParams, err := router.FindRoute(req)
	if err != nil {
		return actual, fmt.Errorf("match OpenAPI route: %w", err)
	}
	binding := policies.forRoute(route)
	if binding == nil {
		return actual, fmt.Errorf("no policy binding for %s %s", route.Method, route.Path)
	}
	inputs := &requestInputs{
		w: httptest.NewRecorder(), r: req,
		route: route, binding: binding, pathParams: pathParams,
		values: policies.values, maxBodyBytes: cfg.MaxBodyBytes,
		fixtureClaims: fixture.Claims, fixtureUserinfo: fixture.Userinfo,
		fixtureIntrospection: fixture.Introspection, offline: true,
	}
	if failure := inputs.requireScopes(binding.requiredScopes); failure != nil {
		return fixtureDenied(actual, failure.status, failure.code), nil
	}
	allowed, failure := binding.rule.evaluate(inputs, binding.params)
	if failure != nil {
		return fixtureDenied(actual, failure.status, failure.code), nil
	}
	if !allowed {
		return fixtureDenied(actual, binding.deny.Response.Status, outcomeCode(binding.deny.Response.Code)), nil
	}
	actual.Allowed = true
	actual.BackendAuth = binding.backendName
	return actual, nil
}

func fixtureDenied(result fixtureResult, status int, code outcomeCode) fixtureResult {
	result.Status = status
	result.Code = string(code)
	return result
}
