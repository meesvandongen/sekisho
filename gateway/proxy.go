package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"go.opentelemetry.io/otel/baggage"
)

type proxyHandler struct {
	cfg         Config
	router      routers.Router
	verifier    *oidc.IDTokenVerifier
	authClient  *http.Client
	sources     *identitySources
	policies    *policySet
	proxy       *httputil.ReverseProxy
	slots       chan struct{}
	auditLogger *slog.Logger
	metrics     requestMetrics
}

const maxOpenAPIBytes = 8 << 20

func newProxy(ctx context.Context, cfg Config) (*proxyHandler, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	target, err := parseEndpoint("upstream_url", cfg.UpstreamURL, false)
	if err != nil {
		return nil, err
	}
	router, policies, err := newPolicyRouter(ctx, cfg)
	if err != nil {
		return nil, err
	}
	authClient := newAuthHTTPClient(cfg.MaxHeaderBytes, cfg.MaxConcurrentRequests)
	verifier, err := newVerifier(ctx, cfg.OIDC, authClient)
	if err != nil {
		return nil, fmt.Errorf("configure OIDC verifier: %w", err)
	}
	sources, err := newIdentitySources(cfg.Identity, authClient,
		policies.needs("userinfo"), policies.needs("introspection"))
	if err != nil {
		return nil, err
	}
	backends := make(map[string]*backendAuth)
	for _, route := range policies.order {
		switch route.backendName {
		case "none", "forward":
			continue
		}
		authConfig := cfg.BackendAuth
		if route.backendName != "default" {
			authConfig = cfg.BackendAuthProfiles[route.backendName]
		}
		if authConfig.GrantType == "none" {
			continue
		}
		if backends[route.backendName] == nil {
			backends[route.backendName], err = newBackendAuth(authConfig, authClient)
			if err != nil {
				return nil, fmt.Errorf("backend auth profile %q: %w", route.backendName, err)
			}
		}
		route.backend = backends[route.backendName]
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = int64(cfg.MaxHeaderBytes)
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DisableCompression = true
	transport.MaxIdleConnsPerHost = cfg.MaxConcurrentRequests
	reverseProxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			req.Out.Header.Del("Forwarded")
			req.Out.Header.Del("X-Forwarded-For")
			req.Out.Header.Del("X-Forwarded-Host")
			req.Out.Header.Del("X-Forwarded-Proto")
			req.Out.Header.Del("X-Real-Ip")
			req.Out.Header.Del("Proxy-Authorization")
			req.Out.Header.Del("X-Forwarded-Authorization")
			req.Out.Header.Del("X-Original-Authorization")
			req.Out.Header.Del("X-Proxy-Outcome")
			req.Out.Header.Del("X-Proxy-Trace-ID")
			req.Out.Header.Del("Baggage")
			req.SetXForwarded()
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("X-Proxy-Outcome", string(classifyUpstreamStatus(resp.StatusCode)))
			resp.Header.Del("X-Proxy-Trace-ID")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			code, status := outcomeUpstreamUnavailable, http.StatusBadGateway
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				code, status = outcomeBodyTooLarge, http.StatusRequestEntityTooLarge
			} else {
				var timeout net.Error
				if errors.Is(err, context.DeadlineExceeded) ||
					(errors.As(err, &timeout) && timeout.Timeout()) {
					code, status = outcomeUpstreamTimeout, http.StatusGatewayTimeout
				}
			}
			if result, ok := r.Context().Value(outcomeContextKey{}).(*requestOutcome); ok {
				result.code = code
				if code == outcomeBodyTooLarge {
					result.phase = "request_body"
				}
			}
			writeProblem(w, r, status, code)
		},
	}
	metrics, err := newRequestMetrics()
	if err != nil {
		return nil, fmt.Errorf("create request metrics: %w", err)
	}
	handler := &proxyHandler{
		cfg: cfg, router: router, verifier: verifier, authClient: authClient,
		sources: sources, policies: policies, proxy: reverseProxy,
		slots: make(chan struct{}, cfg.MaxConcurrentRequests), metrics: metrics,
	}
	if cfg.Audit.isEnabled() {
		handler.auditLogger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return handler, nil
}

func newPolicyRouter(ctx context.Context, cfg Config) (routers.Router, *policySet, error) {
	file, err := os.Open(cfg.OpenAPIFile)
	if err != nil {
		return nil, nil, fmt.Errorf("open OpenAPI spec: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxOpenAPIBytes+1))
	closeErr := file.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("read OpenAPI spec: %w", err)
	}
	if closeErr != nil {
		return nil, nil, fmt.Errorf("close OpenAPI spec: %w", closeErr)
	}
	if len(data) > maxOpenAPIBytes {
		return nil, nil, fmt.Errorf("OpenAPI spec exceeds %d bytes", maxOpenAPIBytes)
	}
	loader := openapi3.NewLoader()
	loader.Context = ctx
	spec, err := loader.LoadFromData(data)
	if err != nil {
		return nil, nil, fmt.Errorf("load OpenAPI spec: %w", err)
	}
	if err := spec.Validate(ctx); err != nil {
		return nil, nil, fmt.Errorf("validate OpenAPI spec: %w", err)
	}
	if spec.Paths == nil || spec.Paths.Len() == 0 {
		return nil, nil, fmt.Errorf("OpenAPI spec has no paths")
	}
	policies, err := compilePolicies(cfg, spec)
	if err != nil {
		return nil, nil, err
	}

	// Match public paths, not the backend host or base paths in OpenAPI servers.
	spec.Servers = openapi3.Servers{{URL: "/"}}
	for _, pathItem := range spec.Paths.Map() {
		pathItem.Servers = nil
	}
	router, err := gorillamux.NewRouter(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("build OpenAPI router: %w", err)
	}
	return router, policies, nil
}

type outcomeContextKey struct{}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	result := &requestOutcome{code: outcomeInternalError, phase: "admission"}
	writer := &outcomeWriter{ResponseWriter: w}
	if id := traceID(r.Context()); id != "" {
		writer.Header().Set("X-Proxy-Trace-ID", id)
	}
	h.metrics.active.Add(r.Context(), 1)
	defer func() {
		if recovered := recover(); recovered != nil {
			result.code = outcomeInternalError
			if recovered == http.ErrAbortHandler {
				result.code = outcomeStreamAborted
				result.phase = "upstream"
			}
			h.finishRequest(r, writer, result, start)
			panic(recovered)
		}
		h.finishRequest(r, writer, result, start)
	}()
	h.serve(writer, r, result)
}

func (h *proxyHandler) serve(w http.ResponseWriter, r *http.Request, result *requestOutcome) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		reject(w, r, result, http.StatusTooManyRequests, outcomeRateLimited)
		return
	}
	if r.ContentLength > h.cfg.MaxBodyBytes {
		result.phase = "request_body"
		reject(w, r, result, http.StatusRequestEntityTooLarge, outcomeBodyTooLarge)
		return
	}
	result.phase = "route"
	if ambiguousPath(r.URL) {
		reject(w, r, result, http.StatusBadRequest, outcomeAmbiguousPath)
		return
	}
	route, pathParams, err := h.router.FindRoute(r)
	if err != nil {
		switch {
		case errors.Is(err, routers.ErrPathNotFound):
			reject(w, r, result, http.StatusNotFound, outcomeRouteNotFound)
		case errors.Is(err, routers.ErrMethodNotAllowed):
			reject(w, r, result, http.StatusMethodNotAllowed, outcomeMethodNotAllowed)
		default:
			reject(w, r, result, http.StatusInternalServerError, outcomeRoutingError)
		}
		return
	}
	result.route = route.Path
	result.operation = route.Operation.OperationID
	compiled := h.policies.forRoute(route)
	if compiled == nil {
		reject(w, r, result, http.StatusInternalServerError, outcomeRoutingError)
		return
	}
	result.policy = compiled.owner()
	result.phase = "authentication"
	rawToken, invalidHeader := bearerToken(r)
	if invalidHeader != "" {
		reject(w, r, result, http.StatusUnauthorized, invalidHeader)
		return
	}
	token, err := h.verifier.Verify(oidc.ClientContext(r.Context(), h.authClient), rawToken)
	if err != nil {
		code := outcomeAuthInvalid
		var expired *oidc.TokenExpiredError
		if errors.As(err, &expired) {
			code = outcomeAuthExpired
		}
		reject(w, r, result, http.StatusUnauthorized, code)
		return
	}
	if h.auditLogger != nil {
		result.subjectHash = verifiedSubjectHash(token.Issuer, token.Subject)
	}
	inputs := &requestInputs{
		w: w, r: r, route: route, compiled: compiled, pathParams: pathParams,
		token: token, rawToken: rawToken, values: h.policies.values,
		sources: h.sources, maxBodyBytes: h.cfg.MaxBodyBytes,
	}
	result.phase = "policy"
	decision := compiled.decide(inputs)
	if decision.binding != nil {
		result.policy = decision.binding.name
	}
	if decision.failure != nil {
		if decision.scopes {
			result.phase = "authorization"
		}
		result.dependencyStatus = decision.failure.dependencyStatus
		reject(w, r, result, decision.failure.status, decision.failure.code)
		return
	}
	if decision.denied {
		deny := decision.binding.deny
		result.reason = deny.Log.Reason
		result.logLevel = deny.Log.Level
		result.logMessage = deny.Log.Message
		code := outcomeCode(deny.Response.Code)
		result.code = code
		writeProblemDetail(w, r, deny.Response.Status, code, deny.Response.Detail)
		return
	}
	result.phase = "backend_auth"
	r = r.WithContext(baggage.ContextWithBaggage(r.Context(), baggage.Baggage{}))
	r.Header.Del("Baggage")
	switch {
	case compiled.backendName == "forward":
		r.Header.Set("Authorization", "Bearer "+rawToken)
	case compiled.backend != nil:
		backendToken, err := compiled.backend.token(r.Context(), rawToken, token.Expiry)
		if err != nil {
			code := outcomeBackendInvalid
			var tokenError *backendTokenError
			if errors.As(err, &tokenError) {
				code = tokenError.code
				result.dependencyStatus = tokenError.status
			}
			reject(w, r, result, http.StatusBadGateway, code)
			return
		}
		r.Header.Set("Authorization", "Bearer "+backendToken)
	default:
		r.Header.Del("Authorization")
	}
	if !inputs.bodyLoaded {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
		}
	}
	result.phase = "upstream"
	result.code = outcomeForwarded
	h.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), outcomeContextKey{}, result)))
}

func reject(w http.ResponseWriter, r *http.Request, result *requestOutcome, status int, code outcomeCode) {
	result.code = code
	writeProblem(w, r, status, code)
}

func ambiguousPath(path *url.URL) bool {
	escaped := strings.ToLower(path.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") ||
		strings.Contains(path.Path, "\\") {
		return true
	}
	for _, segment := range strings.Split(path.Path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}
