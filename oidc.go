package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const maxAuthResponseBytes = 1 << 20

func newAuthHTTPClient(maxHeaderBytes, maxConcurrentRequests int) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = int64(maxHeaderBytes)
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.DisableCompression = true
	transport.MaxIdleConnsPerHost = maxConcurrentRequests
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &cappedResponseTransport{
			base: transport,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type cappedResponseTransport struct {
	base http.RoundTripper
}

func (t *cappedResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, maxAuthResponseBytes)
	return resp, nil
}

func newVerifier(ctx context.Context, cfg OIDCConfig, client *http.Client) (*oidc.IDTokenVerifier, error) {
	options := &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: cfg.Algorithms,
	}
	clientContext := oidc.ClientContext(context.Background(), client)
	if cfg.JWKSURI != "" {
		keys := oidc.NewRemoteKeySet(clientContext, cfg.JWKSURI)
		return oidc.NewVerifier(cfg.Issuer, keys, options), nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, err
	}
	return provider.VerifierContext(clientContext, options), nil
}

func bearerToken(r *http.Request) (string, outcomeCode) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", outcomeAuthMissing
	}
	if len(values) != 1 || len(values[0]) < len("Bearer x") ||
		!strings.EqualFold(values[0][:6], "Bearer") || values[0][6] != ' ' {
		return "", outcomeAuthMalformed
	}
	token := values[0][7:]
	if strings.ContainsAny(token, " \t\r\n,") {
		return "", outcomeAuthMalformed
	}
	return token, ""
}
