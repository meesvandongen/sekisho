package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	colmetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestCompileTimeOTLP(t *testing.T) {
	if os.Getenv("OTELC_INTEGRATION_TEST") != "1" {
		t.Skip("set OTELC_INTEGRATION_TEST=1 to build and exercise the otelc binary")
	}
	issuer := newTestIssuer(t)
	traces := make(chan *coltrace.ExportTraceServiceRequest, 32)
	metrics := make(chan *colmetric.ExportMetricsServiceRequest, 32)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/v1/traces":
			var exported coltrace.ExportTraceServiceRequest
			if err := proto.Unmarshal(data, &exported); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			traces <- &exported
		case "/v1/metrics":
			var exported colmetric.ExportMetricsServiceRequest
			if err := proto.Unmarshal(data, &exported); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			metrics <- &exported
		default:
			t.Errorf("unexpected OTLP path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	tokenTraceparent := make(chan string, 1)
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenTraceparent <- r.Header.Get("Traceparent")
		if r.Header.Get("Baggage") != "" || r.FormValue("grant_type") != tokenExchangeGrant {
			t.Error("unsafe token exchange")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w,
			`{"access_token":"backend-token","token_type":"Bearer","issued_token_type":"`+
				accessTokenType+`","expires_in":300}`)
	}))
	t.Cleanup(tokenEndpoint.Close)
	upstreamTraceparent := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamTraceparent <- r.Header.Get("Traceparent")
		if r.Header.Get("Authorization") != "Bearer backend-token" || r.Header.Get("Baggage") != "" {
			t.Error("unsafe forwarded request")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.Listen = address
	cfg.BackendAuth = BackendAuthConfig{
		GrantType: "token_exchange", TokenURL: tokenEndpoint.URL,
		ClientID: "client", ClientAuth: "client_secret_basic",
		ClientSecretEnv: "SEKISHO_OTELC_TEST_SECRET",
	}
	cfg.Policy.Routes[0].Auth.Backend = "default"
	configPath := filepath.Join(t.TempDir(), "config.json")
	configData, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "proxy")
	build := exec.Command("go", "tool", "otelc", "go", "build", "-buildvcs=false", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("otelc build failed: %v\n%s", err, output)
	}
	var stdout, stderr bytes.Buffer
	command := exec.Command(binary, "-config", configPath)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"OTEL_SERVICE_NAME=proxy-integration-test",
		"OTEL_EXPORTER_OTLP_ENDPOINT=" + collector.URL,
		"OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
		"OTEL_TRACES_EXPORTER=otlp",
		"OTEL_METRICS_EXPORTER=otlp",
		"OTEL_LOGS_EXPORTER=none",
		"OTEL_BSP_SCHEDULE_DELAY=100",
		"OTEL_METRIC_EXPORT_INTERVAL=100",
		"SEKISHO_OTELC_TEST_SECRET=client-secret",
	}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v\nstdout: %s\nstderr: %s", err, &stdout, &stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	token := issuer.sign(t, map[string]any{"sub": "private-identity"})
	request := authedRequest(t, http.MethodGet, "http://"+address+"/items?tenant=blue", token, "")
	request.Header.Set("Traceparent", "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01")
	request.Header.Set("Baggage", "secret=do-not-forward")
	status, body, headers := sendRequest(t, request)
	if status != http.StatusNoContent || headers.Get("X-Proxy-Outcome") != string(outcomeForwarded) {
		t.Fatalf("instrumented request: HTTP %d: %s", status, body)
	}
	traceID := headers.Get("X-Proxy-Trace-ID")
	if traceID != "1234567890abcdef1234567890abcdef" {
		t.Fatalf("request span trace ID = %q", traceID)
	}
	denied := authedRequest(t, http.MethodGet, "http://"+address+"/items", "invalid", "")
	denied.Header.Set("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	status, body, headers = sendRequest(t, denied)
	if status != http.StatusUnauthorized || headers.Get("X-Proxy-Outcome") != string(outcomeAuthInvalid) ||
		!strings.Contains(body, `"trace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`) {
		t.Fatalf("instrumented denial: HTTP %d: %s", status, body)
	}
	for _, received := range []string{<-tokenTraceparent, <-upstreamTraceparent} {
		if !strings.HasPrefix(received, "00-"+traceID+"-") {
			t.Fatalf("outbound trace context = %q", received)
		}
	}

	var allowedSpan, deniedSpan, allowedMetric, deniedMetric bool
	timeout := time.After(5 * time.Second)
	for !allowedSpan || !deniedSpan || !allowedMetric || !deniedMetric {
		select {
		case exported := <-traces:
			for _, resourceSpans := range exported.ResourceSpans {
				var serviceName string
				for _, attr := range resourceSpans.Resource.Attributes {
					if attr.Key == "service.name" {
						serviceName = attr.Value.GetStringValue()
					}
				}
				if serviceName != "proxy-integration-test" {
					t.Fatalf("OTEL_SERVICE_NAME was ignored: %q", serviceName)
				}
				for _, scopeSpans := range resourceSpans.ScopeSpans {
					for _, span := range scopeSpans.Spans {
						if span.Name != "GET /items" {
							continue
						}
						attributes := make(map[string]string)
						for _, attr := range span.Attributes {
							attributes[attr.Key] = attr.Value.GetStringValue()
						}
						if attributes["http.route"] != "/items" || attributes["proxy.operation"] != "listItems" {
							t.Fatalf("missing route attributes: %v", attributes)
						}
						switch fmt.Sprintf("%x", span.TraceId) {
						case traceID:
							allowedSpan = attributes["proxy.outcome"] == string(outcomeForwarded)
						case "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
							deniedSpan = attributes["proxy.outcome"] == string(outcomeAuthInvalid)
						}
					}
				}
			}
		case exported := <-metrics:
			for _, resourceMetrics := range exported.ResourceMetrics {
				for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
					for _, measure := range scopeMetrics.Metrics {
						if measure.Name != "proxy.requests" {
							continue
						}
						for _, point := range measure.GetSum().DataPoints {
							labels := make(map[string]string)
							for _, attr := range point.Attributes {
								labels[attr.Key] = attr.Value.GetStringValue()
							}
							if labels["http.route"] != "/items" || labels["http.request.method"] != "GET" {
								t.Fatalf("incorrect metric labels: %v", labels)
							}
							switch labels["proxy.outcome"] {
							case string(outcomeForwarded):
								allowedMetric = point.GetAsInt() >= 1
							case string(outcomeAuthInvalid):
								deniedMetric = point.GetAsInt() >= 1
							}
						}
					}
				}
			}
		case <-timeout:
			t.Fatalf("missing OTLP signals: spans=%t/%t metrics=%t/%t\nstdout: %s\nstderr: %s",
				allowedSpan, deniedSpan, allowedMetric, deniedMetric, &stdout, &stderr)
		}
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		waited = true
		if err != nil {
			t.Fatalf("proxy shutdown: %v\nstdout: %s\nstderr: %s", err, &stdout, &stderr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not shut down")
	}
	if strings.Count(stderr.String(), `"trace_id":"`+traceID+`"`) != 1 ||
		strings.Contains(stderr.String(), token) || strings.Contains(stdout.String(), token) {
		t.Fatalf("audit trace correlation or redaction failed\nstdout: %s\nstderr: %s", &stdout, &stderr)
	}

	var disabledOutput bytes.Buffer
	disabled := exec.Command(binary, "-config", configPath)
	disabled.Env = append(append([]string(nil), command.Env...), "OTEL_SDK_DISABLED=true")
	disabled.Stdout = &disabledOutput
	disabled.Stderr = &disabledOutput
	if err := disabled.Start(); err != nil {
		t.Fatal(err)
	}
	disabledWaited := false
	defer func() {
		if !disabledWaited {
			_ = disabled.Process.Kill()
			_ = disabled.Wait()
		}
	}()
	deadline = time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("disabled proxy did not start: %v\n%s", err, &disabledOutput)
		}
		time.Sleep(20 * time.Millisecond)
	}
	request = authedRequest(t, http.MethodGet, "http://"+address+"/items", token, "")
	request.Header.Set("Traceparent", "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01")
	status, body, headers = sendRequest(t, request)
	if status != http.StatusNoContent || headers.Get("X-Proxy-Outcome") != string(outcomeForwarded) ||
		headers.Get("X-Proxy-Trace-ID") != "" {
		t.Fatalf("disabled SDK altered proxy behavior: HTTP %d: %s, headers %v", status, body, headers)
	}
	if err := disabled.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wait = make(chan error, 1)
	go func() { wait <- disabled.Wait() }()
	select {
	case err := <-wait:
		disabledWaited = true
		if err != nil {
			t.Fatalf("disabled proxy shutdown: %v\n%s", err, &disabledOutput)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("disabled proxy did not shut down")
	}
}
