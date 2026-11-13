package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

type auditChannel struct {
	events chan []byte
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (c auditChannel) Write(data []byte) (int, error) {
	c.events <- append([]byte(nil), data...)
	return len(data), nil
}

func TestFailureOutcomesAndAudit(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("inbound bearer reached upstream: %q", got)
		}
		if r.URL.Path == "/items/fail" {
			w.Header().Set("X-Proxy-Outcome", "spoofed")
			w.Header().Set("X-Proxy-Trace-ID", "spoofed")
			http.Error(w, "upstream response", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Proxy-Outcome", "spoofed")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.MaxBodyBytes = 32
	setTestPolicy(t, &cfg, "getItem", `claims.sub == "sensitive-subject" && path_params.id != "denied"`)
	setTestPolicy(t, &cfg, "createItem", `body.allowed == true && body.missing.value == 1`)
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	handler.auditLogger = slog.New(slog.NewJSONHandler(&audit, nil))
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	valid := issuer.sign(t, map[string]any{"sub": "sensitive-subject"})
	expired := issuer.sign(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	wrongAudience := issuer.sign(t, map[string]any{"aud": "wrong"})
	tests := []struct {
		name, method, path, token, body, contentType string
		status                                       int
		code                                         outcomeCode
		phase                                        string
		verified                                     bool
		problem                                      bool
	}{
		{"missing auth", "GET", "/items/ok", "", "", "", 401, outcomeAuthMissing, "authentication", false, true},
		{"bad auth", "GET", "/items/ok", "not-a-token", "", "", 401, outcomeAuthInvalid, "authentication", false, true},
		{"wrong audience", "GET", "/items/ok", wrongAudience, "", "", 401, outcomeAuthInvalid, "authentication", false, true},
		{"expired", "GET", "/items/ok", expired, "", "", 401, outcomeAuthExpired, "authentication", false, true},
		{"route", "GET", "/missing", "", "", "", 404, outcomeRouteNotFound, "route", false, true},
		{"method", "DELETE", "/items", "", "", "", 405, outcomeMethodNotAllowed, "route", false, true},
		{"path", "GET", "/items/a%2Fb", "", "", "", 400, outcomeAmbiguousPath, "route", false, true},
		{"policy denied", "GET", "/items/denied", valid, "", "", 403, outcomePolicyDenied, "policy", true, true},
		{"invalid JSON", "POST", "/items", valid, "{", "application/json", 400, outcomeInvalidJSON, "policy", true, true},
		{"unsupported media", "POST", "/items", valid, "plain", "text/plain", 415, outcomeUnsupportedMedia, "policy", true, true},
		{"policy error", "POST", "/items", valid, `{"allowed":true}`, "application/json", 403, outcomePolicyError, "policy", true, true},
		{"body limit", "POST", "/items", valid, strings.Repeat("x", 33), "application/json", 413, outcomeBodyTooLarge, "request_body", false, true},
		{"forwarded", "GET", "/items/ok?secret=do-not-log", valid, "", "", 204, outcomeForwarded, "upstream", true, false},
		{"upstream failure", "GET", "/items/fail", valid, "", "", 503, outcomeUpstreamFailure, "upstream", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := authedRequest(t, tc.method, proxy.URL+tc.path, tc.token, tc.body)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			status, body, headers := sendRequest(t, req)
			if status != tc.status || headers.Get("X-Proxy-Outcome") != string(tc.code) {
				t.Fatalf("HTTP %d, outcome %q; want %d/%q: %s",
					status, headers.Get("X-Proxy-Outcome"), tc.status, tc.code, body)
			}
			if headers.Get("X-Proxy-Trace-ID") != "" {
				t.Fatalf("unexpected trace ID with OTel disabled: %q", headers.Get("X-Proxy-Trace-ID"))
			}
			if tc.problem {
				if got := headers.Get("Content-Type"); got != "application/problem+json" {
					t.Fatalf("problem Content-Type = %q", got)
				}
				var problem struct {
					Type, Title, Code, TraceID string
					Status                     int
				}
				if err := json.Unmarshal([]byte(body), &problem); err != nil {
					t.Fatal(err)
				}
				if problem.Type != "about:blank" || problem.Status != status ||
					problem.Code != string(tc.code) || problem.TraceID != "" {
					t.Fatalf("unexpected problem: %+v", problem)
				}
				if status == http.StatusUnauthorized && headers.Get("WWW-Authenticate") != "Bearer" {
					t.Fatal("missing bearer challenge")
				}
			}
		})
	}
	var events []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(audit.Bytes()), []byte{'\n'}) {
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("invalid JSON audit event: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != len(tests) {
		t.Fatalf("got %d audit events, want %d", len(events), len(tests))
	}
	for i, event := range events {
		tc := tests[i]
		if event["event"] != "proxy.request" || event["outcome"] != string(tc.code) ||
			event["status"] != float64(tc.status) || event["phase"] != tc.phase {
			t.Fatalf("audit event %d: %+v", i, event)
		}
		if tc.verified {
			if event["subject_sha256"] != verifiedSubjectHash(issuer.server.URL, "sensitive-subject") {
				t.Fatalf("audit event %d missing verified identity hash: %+v", i, event)
			}
		} else if _, ok := event["subject_sha256"]; ok {
			t.Fatalf("audit event %d identifies an unverified caller", i)
		}
	}
	for _, secret := range []string{"sensitive-subject", "do-not-log", valid, wrongAudience} {
		if strings.Contains(audit.String(), secret) {
			t.Fatalf("audit leaked request data %q", secret)
		}
	}
}

func TestBackendAndUpstreamErrorOutcomes(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("SEKISHO_OUTCOME_SECRET", "client-secret")
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "server secret: not-for-logs")
	}))
	t.Cleanup(tokenServer.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.BackendAuth = BackendAuthConfig{
		GrantType: "client_credentials", TokenURL: tokenServer.URL,
		ClientID: "client", ClientAuth: "client_secret_basic",
		ClientSecretEnv: "SEKISHO_OUTCOME_SECRET",
	}
	cfg.Policy.Routes[0].Auth.Backend = "default"
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	handler.auditLogger = slog.New(slog.NewJSONHandler(&audit, nil))
	proxy := httptest.NewServer(handler)
	req := authedRequest(t, "GET", proxy.URL+"/items", issuer.sign(t, nil), "")
	status, body, headers := sendRequest(t, req)
	proxy.Close()
	if status != 502 || headers.Get("X-Proxy-Outcome") != string(outcomeBackendRejected) {
		t.Fatalf("token endpoint rejected: HTTP %d: %s", status, body)
	}
	if !strings.Contains(audit.String(), `"dependency_status":403`) ||
		strings.Contains(audit.String(), "not-for-logs") || strings.Contains(body, "not-for-logs") {
		t.Fatalf("unsafe or missing dependency outcome: audit=%s response=%s", audit.String(), body)
	}

	cfg.BackendAuth = BackendAuthConfig{}
	cfg.Policy.Routes[0].Auth.Backend = "none"
	upstream.Close()
	unavailable := startTestProxy(t, cfg)
	req = authedRequest(t, "GET", unavailable.URL+"/items", issuer.sign(t, nil), "")
	status, body, headers = sendRequest(t, req)
	if status != 502 || headers.Get("X-Proxy-Outcome") != string(outcomeUpstreamUnavailable) {
		t.Fatalf("unavailable upstream: HTTP %d: %s", status, body)
	}

	handler, err = newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler.proxy.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})
	timedOut := httptest.NewServer(handler)
	t.Cleanup(timedOut.Close)
	req = authedRequest(t, "GET", timedOut.URL+"/items", issuer.sign(t, nil), "")
	status, body, headers = sendRequest(t, req)
	if status != http.StatusGatewayTimeout ||
		headers.Get("X-Proxy-Outcome") != string(outcomeUpstreamTimeout) {
		t.Fatalf("timed-out upstream: HTTP %d: %s", status, body)
	}
}

func TestRequestSpanAnnotations(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	handler.auditLogger = slog.New(slog.NewJSONHandler(&audit, nil))
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		token string
		code  outcomeCode
		want  int
	}{
		{issuer.sign(t, nil), outcomeForwarded, http.StatusNoContent},
		{"invalid", outcomeAuthInvalid, http.StatusUnauthorized},
	} {
		ctx, span := provider.Tracer("test").Start(context.Background(), "HTTP", trace.WithSpanKind(trace.SpanKindServer))
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test/items", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		span.End()
		if w.Code != tc.want || w.Header().Get("X-Proxy-Trace-ID") != span.SpanContext().TraceID().String() {
			t.Fatalf("request outcome: HTTP %d, headers %v", w.Code, w.Header())
		}
		spans := exporter.GetSpans()
		found := spans[len(spans)-1]
		attrs := make(map[string]string)
		for _, attr := range found.Attributes {
			attrs[string(attr.Key)] = attr.Value.Emit()
		}
		if found.Name != "GET /items" || attrs["proxy.outcome"] != string(tc.code) ||
			attrs["http.route"] != "/items" || attrs["proxy.operation"] != "listItems" {
			t.Fatalf("missing request span annotations: %+v", found)
		}
	}
	if !strings.Contains(audit.String(), `"trace_id":`) {
		t.Fatalf("audit missing trace correlation: %s", audit.String())
	}
}

func TestDisabledAudit(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	disabled := false
	cfg.Audit.Enabled = &disabled
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if handler.auditLogger != nil {
		t.Fatal("audit logger initialized while disabled")
	}
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	req := authedRequest(t, "GET", proxy.URL+"/items", issuer.sign(t, nil), "")
	status, _, headers := sendRequest(t, req)
	if status != http.StatusNoContent || headers.Get("X-Proxy-Trace-ID") != "" {
		t.Fatalf("disabled observability: HTTP %d: %v", status, headers)
	}
}

func TestStreamingResponsePreservesFlush(t *testing.T) {
	issuer := newTestIssuer(t)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "second\n")
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	proxy := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", issuer.sign(t, nil), "")
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		t.Fatalf("first streamed chunk = %q: %v", first, err)
	}
	close(release)
	second, err := reader.ReadString('\n')
	if err != nil || second != "second\n" {
		t.Fatalf("second streamed chunk = %q: %v", second, err)
	}
}

func TestUpgradeAuditRecordsSwitchingProtocols(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Upgrade") != "chat" {
			http.Error(w, "bad upgrade", http.StatusBadRequest)
			return
		}
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := buffered.WriteString(
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: chat\r\n\r\n",
		); err != nil {
			t.Error(err)
			return
		}
		if err := buffered.Flush(); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.Copy(io.Discard, conn)
	}))
	t.Cleanup(upstream.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	handler, err := newProxy(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	audit := auditChannel{events: make(chan []byte, 1)}
	handler.auditLogger = slog.New(slog.NewJSONHandler(audit, nil))
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	token := issuer.sign(t, nil)
	if _, err := fmt.Fprintf(conn,
		"GET /items HTTP/1.1\r\nHost: proxy.test\r\nAuthorization: Bearer %s\r\nConnection: Upgrade\r\nUpgrade: chat\r\n\r\n",
		token,
	); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		resp.Header.Get("X-Proxy-Outcome") != string(outcomeForwarded) {
		t.Fatalf("upgrade response: HTTP %d: %v", resp.StatusCode, resp.Header)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case data := <-audit.events:
		var event map[string]any
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal(err)
		}
		if event["status"] != float64(http.StatusSwitchingProtocols) ||
			event["outcome"] != string(outcomeForwarded) {
			t.Fatalf("upgrade audit event: %+v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upgrade audit event not emitted")
	}
}
