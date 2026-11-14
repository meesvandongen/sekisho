package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type outcomeCode string

const (
	outcomeForwarded                outcomeCode = "forwarded"
	outcomeAllowed                  outcomeCode = "allowed"
	outcomeAuthRequestInvalid       outcomeCode = "auth_request_invalid"
	outcomeUpstreamRejected         outcomeCode = "upstream_rejected"
	outcomeUpstreamFailure          outcomeCode = "upstream_failure"
	outcomeUpstreamUnavailable      outcomeCode = "upstream_unavailable"
	outcomeUpstreamTimeout          outcomeCode = "upstream_timeout"
	outcomeStreamAborted            outcomeCode = "upstream_stream_aborted"
	outcomeInternalError            outcomeCode = "internal_error"
	outcomeRateLimited              outcomeCode = "rate_limited"
	outcomeBodyTooLarge             outcomeCode = "body_too_large"
	outcomeAmbiguousPath            outcomeCode = "ambiguous_path"
	outcomeRouteNotFound            outcomeCode = "route_not_found"
	outcomeMethodNotAllowed         outcomeCode = "method_not_allowed"
	outcomeRoutingError             outcomeCode = "routing_error"
	outcomeAuthMissing              outcomeCode = "auth_missing"
	outcomeAuthMalformed            outcomeCode = "auth_malformed"
	outcomeAuthExpired              outcomeCode = "auth_expired"
	outcomeAuthInvalid              outcomeCode = "auth_invalid"
	outcomeInsufficientScope        outcomeCode = "insufficient_scope"
	outcomeClaimsInvalid            outcomeCode = "claims_invalid"
	outcomePolicyDenied             outcomeCode = "policy_denied"
	outcomePolicyError              outcomeCode = "policy_error"
	outcomeInvalidQuery             outcomeCode = "invalid_query"
	outcomeInvalidJSON              outcomeCode = "invalid_json"
	outcomeInvalidBodyText          outcomeCode = "invalid_body_text"
	outcomeBodyReadError            outcomeCode = "body_read_error"
	outcomeUnsupportedMedia         outcomeCode = "unsupported_media_type"
	outcomeBackendUnavailable       outcomeCode = "backend_token_unavailable"
	outcomeBackendRejected          outcomeCode = "backend_token_rejected"
	outcomeBackendInvalid           outcomeCode = "backend_token_invalid"
	outcomeBackendAssertion         outcomeCode = "backend_assertion_failed"
	outcomeUserinfoUnavailable      outcomeCode = "userinfo_unavailable"
	outcomeUserinfoInvalid          outcomeCode = "userinfo_invalid"
	outcomeUserinfoMismatch         outcomeCode = "userinfo_subject_mismatch"
	outcomeIntrospectionUnavailable outcomeCode = "introspection_unavailable"
	outcomeIntrospectionInvalid     outcomeCode = "introspection_invalid"
	outcomeIntrospectionMismatch    outcomeCode = "introspection_subject_mismatch"
	outcomeTokenInactive            outcomeCode = "token_inactive"
)

type requestOutcome struct {
	code             outcomeCode
	phase            string
	method           string
	route            string
	operation        string
	policy           string
	reason           string
	logLevel         string
	logMessage       string
	subjectHash      string
	dependencyStatus int
}

type requestMetrics struct {
	requests metric.Int64Counter
	duration metric.Float64Histogram
	active   metric.Int64UpDownCounter
}

func newRequestMetrics() (requestMetrics, error) {
	meter := otel.Meter("sekisho")
	var instruments requestMetrics
	var err error
	instruments.requests, err = meter.Int64Counter("proxy.requests", metric.WithUnit("{request}"))
	if err != nil {
		return instruments, err
	}
	instruments.duration, err = meter.Float64Histogram(
		"proxy.request.duration", metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10),
	)
	if err != nil {
		return instruments, err
	}
	instruments.active, err = meter.Int64UpDownCounter("proxy.requests.active", metric.WithUnit("{request}"))
	return instruments, err
}

type outcomeWriter struct {
	http.ResponseWriter
	status int
}

func (w *outcomeWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *outcomeWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *outcomeWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func classifyUpstreamStatus(status int) outcomeCode {
	switch {
	case status >= 500:
		return outcomeUpstreamFailure
	case status >= 400:
		return outcomeUpstreamRejected
	default:
		return outcomeForwarded
	}
}

func verifiedSubjectHash(issuer, subject string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return hex.EncodeToString(digest[:])
}

func traceID(ctx context.Context) string {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return ""
	}
	return spanContext.TraceID().String()
}

func (h *proxyHandler) finishRequest(r *http.Request, w *outcomeWriter, result *requestOutcome, start time.Time) {
	status := w.status
	if status == 0 {
		if result.code == outcomeForwarded && r.Header.Get("Upgrade") != "" {
			status = http.StatusSwitchingProtocols
		} else {
			status = http.StatusInternalServerError
			if result.code == outcomeForwarded {
				result.code = outcomeInternalError
			}
		}
	}
	if result.code == outcomeForwarded {
		result.code = classifyUpstreamStatus(status)
	}
	if result.code == "" {
		result.code = outcomeInternalError
	}
	duration := time.Since(start)
	if h.auditLogger != nil {
		fields := []any{
			"event", "proxy.request",
			"method", metricMethod(result.method),
			"route", result.route,
			"operation", result.operation,
			"phase", result.phase,
			"outcome", result.code,
			"status", status,
			"duration_ms", float64(duration) / float64(time.Millisecond),
		}
		if result.subjectHash != "" {
			fields = append(fields, "subject_sha256", result.subjectHash)
		}
		if result.policy != "" {
			fields = append(fields, "policy", result.policy)
		}
		if result.reason != "" {
			fields = append(fields, "reason", result.reason)
		}
		if result.dependencyStatus != 0 {
			fields = append(fields, "dependency_status", result.dependencyStatus)
		}
		if id := traceID(r.Context()); id != "" {
			fields = append(fields, "trace_id", id)
		}
		level := slog.LevelInfo
		switch result.logLevel {
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
		message := result.logMessage
		if message == "" {
			message = "proxy request"
		}
		record := slog.Record{Time: time.Now(), Level: level, Message: message}
		record.Add(fields...)
		if err := h.auditLogger.Handler().Handle(r.Context(), record); err != nil {
			log.Printf("audit write failed: %v", err)
		}
	}
	route := result.route
	if route == "" {
		route = "unmatched"
	}
	attributes := []attribute.KeyValue{
		attribute.String("http.request.method", metricMethod(result.method)),
		attribute.String("http.route", route),
		attribute.String("proxy.outcome", string(result.code)),
		attribute.Int("http.response.status_code", status),
	}
	options := metric.WithAttributes(attributes...)
	h.metrics.requests.Add(r.Context(), 1, options)
	h.metrics.duration.Record(r.Context(), duration.Seconds(), options)
	h.metrics.active.Add(r.Context(), -1)

	span := trace.SpanFromContext(r.Context())
	if span.IsRecording() {
		span.SetAttributes(attributes...)
		span.SetAttributes(attribute.String("proxy.phase", result.phase))
		if result.route != "" {
			span.SetName(metricMethod(result.method) + " " + result.route)
		}
		if result.operation != "" {
			span.SetAttributes(attribute.String("proxy.operation", result.operation))
		}
		if status >= 500 {
			span.SetStatus(codes.Error, string(result.code))
		}
	}
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code outcomeCode) {
	writeProblemDetail(w, r, status, code, "")
}

func writeProblemDetail(w http.ResponseWriter, r *http.Request, status int, code outcomeCode, detail string) {
	problem := struct {
		Type    string `json:"type"`
		Title   string `json:"title"`
		Status  int    `json:"status"`
		Code    string `json:"code"`
		Detail  string `json:"detail,omitempty"`
		TraceID string `json:"trace_id,omitempty"`
	}{
		Type: "about:blank", Title: http.StatusText(status),
		Status: status, Code: string(code), Detail: detail, TraceID: traceID(r.Context()),
	}
	data, err := json.Marshal(problem)
	if err != nil {
		log.Printf("encode proxy problem: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Proxy-Outcome", string(code))
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	if _, err := w.Write(append(data, '\n')); err != nil {
		log.Printf("write proxy problem: %v", err)
	}
}

func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}
