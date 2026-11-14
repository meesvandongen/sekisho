package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Response headers of an auth_request decision. The fronting proxy reads them
// with auth_request_set (nginx) or authResponseHeaders (Traefik).
const (
	authRequestAuthorizationHeader = "X-Sekisho-Authorization"
	authRequestStatusHeader        = "X-Sekisho-Status"
)

// authRequestWriter maps decision statuses onto the three outcomes nginx's
// auth_request understands: 2xx allows, 401 and 403 deny, anything else
// becomes a 500. Other client errors are sent as 403 so nginx denies the
// request instead of failing it; the decision's own status is kept in
// X-Sekisho-Status and in the audit log.
type authRequestWriter struct {
	http.ResponseWriter
}

func (w *authRequestWriter) WriteHeader(status int) {
	mapped := status
	switch {
	case status < 300 || status == http.StatusUnauthorized || status == http.StatusForbidden:
	case status < 500:
		mapped = http.StatusForbidden
	default:
		mapped = http.StatusInternalServerError
	}
	header := w.Header()
	header.Set(authRequestStatusHeader, strconv.Itoa(status))
	header.Set("Cache-Control", "no-store")
	header.Del("Retry-After")
	w.ResponseWriter.WriteHeader(mapped)
}

func (w *authRequestWriter) Write(data []byte) (int, error) {
	return w.ResponseWriter.Write(data)
}

func (w *authRequestWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// authRequestError reports a subrequest that does not describe an original
// request. A missing header is a proxy misconfiguration and fails loudly.
type authRequestError struct {
	status int
	err    error
}

func (e *authRequestError) Error() string { return e.err.Error() }

// originalRequest rebuilds the request the fronting proxy is asking about from
// the configured headers. The subrequest's own method, path and body are
// ignored: nginx sends no body (proxy_pass_request_body off), so policies that
// read the body are rejected at startup in this mode.
func originalRequest(r *http.Request, cfg AuthRequestConfig) (*http.Request, *authRequestError) {
	methodValues := r.Header.Values(cfg.MethodHeader)
	uriValues := r.Header.Values(cfg.URIHeader)
	if len(methodValues) == 0 || len(uriValues) == 0 {
		return nil, &authRequestError{
			status: http.StatusInternalServerError,
			err:    fmt.Errorf("auth request is missing %s or %s", cfg.MethodHeader, cfg.URIHeader),
		}
	}
	if len(methodValues) != 1 || len(uriValues) != 1 {
		return nil, &authRequestError{
			status: http.StatusBadRequest,
			err:    fmt.Errorf("auth request headers must appear once"),
		}
	}
	method := methodValues[0]
	if method == "" || strings.ContainsFunc(method, func(char rune) bool {
		return char < '!' || char > '~'
	}) {
		return nil, &authRequestError{status: http.StatusBadRequest, err: fmt.Errorf("invalid original method")}
	}
	rawURI := uriValues[0]
	if !strings.HasPrefix(rawURI, "/") || strings.HasPrefix(rawURI, "//") {
		return nil, &authRequestError{status: http.StatusBadRequest, err: fmt.Errorf("original URI must be origin-form")}
	}
	target, err := url.ParseRequestURI(rawURI)
	if err != nil {
		return nil, &authRequestError{status: http.StatusBadRequest, err: fmt.Errorf("invalid original URI: %w", err)}
	}
	original := r.Clone(r.Context())
	original.Method = method
	original.URL = target
	original.RequestURI = rawURI
	original.Body = http.NoBody
	original.ContentLength = 0
	original.Header.Del(cfg.MethodHeader)
	original.Header.Del(cfg.URIHeader)
	original.Header.Del("Content-Length")
	return original, nil
}
