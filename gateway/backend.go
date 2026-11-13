package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	tokenExchangeGrant   = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType      = "urn:ietf:params:oauth:token-type:access_token"
	clientAssertionType  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	maxPrivateKeyBytes   = 64 << 10
	maxTokenResponseSize = 64 << 10
)

type backendAuth struct {
	cfg    BackendAuthConfig
	client *http.Client
	secret string
	key    *rsa.PrivateKey

	mu            sync.Mutex
	cachedToken   string
	cacheExpires  time.Time
	exchangeCache *boundedCache[string]
	exchangeGroup singleflight.Group
}

type backendTokenError struct {
	code   outcomeCode
	status int
	err    error
}

func (e *backendTokenError) Error() string { return e.err.Error() }
func (e *backendTokenError) Unwrap() error { return e.err }

func newBackendAuth(cfg BackendAuthConfig, client *http.Client) (*backendAuth, error) {
	auth := &backendAuth{cfg: cfg, client: client}
	switch cfg.ClientAuth {
	case "client_secret_basic", "client_secret_post":
		secret, ok := os.LookupEnv(cfg.ClientSecretEnv)
		if !ok || secret == "" {
			return nil, fmt.Errorf("backend client secret environment variable %q is empty", cfg.ClientSecretEnv)
		}
		auth.secret = secret
	case "private_key_jwt":
		key, err := loadPrivateKey(cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("backend private key: %w", err)
		}
		auth.key = key
	}
	if cfg.GrantType == "token_exchange" && cfg.Cache.TTLSeconds > 0 {
		auth.exchangeCache = newBoundedCache[string](cfg.Cache.MaxEntries)
	}
	return auth, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPrivateKeyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPrivateKeyBytes {
		return nil, fmt.Errorf("key file exceeds %d bytes", maxPrivateKeyBytes)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected a single PEM-encoded RSA private key")
	}
	var parsed any
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("private_key_jwt requires an RSA key of at least 2048 bits")
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}

func (a *backendAuth) token(ctx context.Context, subjectToken string, subjectExpiry time.Time) (string, error) {
	switch a.cfg.GrantType {
	case "none":
		return "", nil
	case "token_exchange":
		if a.exchangeCache == nil {
			token, _, err := a.fetch(ctx, subjectToken)
			return token, err
		}
		key := sha256.Sum256([]byte(subjectToken))
		if cached, ok := a.exchangeCache.get(key); ok {
			return cached, nil
		}
		result := a.exchangeGroup.DoChan(string(key[:]), func() (any, error) {
			if cached, ok := a.exchangeCache.get(key); ok {
				return cached, nil
			}
			token, expiresIn, err := a.fetch(ctx, subjectToken)
			if err != nil {
				return nil, err
			}
			if expiresIn > 30 {
				expires := time.Now().Add(time.Duration(min(expiresIn-30, 3600)) * time.Second)
				a.exchangeCache.put(key, token, cacheUntil(a.cfg.Cache.TTLSeconds, expires, subjectExpiry))
			}
			return token, nil
		})
		select {
		case <-ctx.Done():
			return "", &backendTokenError{code: outcomeBackendUnavailable, err: ctx.Err()}
		case exchanged := <-result:
			if exchanged.Err != nil {
				return "", exchanged.Err
			}
			return exchanged.Val.(string), nil
		}
	case "client_credentials":
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.cachedToken != "" && time.Now().Before(a.cacheExpires) {
			return a.cachedToken, nil
		}
		token, expiresIn, err := a.fetch(ctx, "")
		if err != nil {
			return "", err
		}
		a.cachedToken = ""
		if expiresIn > 30 {
			seconds := min(expiresIn-30, 3600)
			a.cachedToken = token
			a.cacheExpires = time.Now().Add(time.Duration(seconds) * time.Second)
		}
		return token, nil
	default:
		return "", &backendTokenError{
			code: outcomeBackendAssertion, err: fmt.Errorf("unsupported backend grant %q", a.cfg.GrantType),
		}
	}
}

func (a *backendAuth) fetch(ctx context.Context, subjectToken string) (string, int64, error) {
	form := url.Values{}
	switch a.cfg.GrantType {
	case "client_credentials":
		form.Set("grant_type", "client_credentials")
	case "token_exchange":
		if subjectToken == "" {
			return "", 0, &backendTokenError{
				code: outcomeBackendAssertion, err: fmt.Errorf("token exchange requires a subject token"),
			}
		}
		form.Set("grant_type", tokenExchangeGrant)
		form.Set("subject_token", subjectToken)
		subjectType := a.cfg.SubjectTokenType
		if subjectType == "" {
			subjectType = accessTokenType
		}
		form.Set("subject_token_type", subjectType)
		requestedType := a.cfg.RequestedTokenType
		if requestedType == "" {
			requestedType = accessTokenType
		}
		form.Set("requested_token_type", requestedType)
	}
	if len(a.cfg.Scope) != 0 {
		form.Set("scope", strings.Join(a.cfg.Scope, " "))
	}
	if a.cfg.Audience != "" {
		form.Set("audience", a.cfg.Audience)
	}
	if a.cfg.Resource != "" {
		form.Set("resource", a.cfg.Resource)
	}
	if err := a.addClientCredentials(form); err != nil {
		return "", 0, &backendTokenError{
			code: outcomeBackendAssertion, err: fmt.Errorf("client authentication: %w", err),
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, &backendTokenError{
			code: outcomeBackendAssertion, err: fmt.Errorf("create token request: %w", err),
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	a.setBasicAuth(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", 0, &backendTokenError{
			code: outcomeBackendUnavailable, err: fmt.Errorf("request backend token: %w", err),
		}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize+1))
	if err != nil {
		return "", 0, &backendTokenError{
			code: outcomeBackendInvalid, err: fmt.Errorf("read token response: %w", err),
		}
	}
	if len(data) > maxTokenResponseSize {
		return "", 0, &backendTokenError{
			code: outcomeBackendInvalid, err: fmt.Errorf("token response exceeds %d bytes", maxTokenResponseSize),
		}
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, &backendTokenError{
			code: outcomeBackendRejected, status: resp.StatusCode,
			err: fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode),
		}
	}
	var result struct {
		AccessToken     string `json:"access_token"`
		TokenType       string `json:"token_type"`
		IssuedTokenType string `json:"issued_token_type"`
		ExpiresIn       int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", 0, &backendTokenError{
			code: outcomeBackendInvalid, err: fmt.Errorf("decode token response: %w", err),
		}
	}
	if !strings.EqualFold(result.TokenType, "Bearer") || result.AccessToken == "" || result.ExpiresIn < 0 {
		return "", 0, &backendTokenError{
			code: outcomeBackendInvalid, err: fmt.Errorf("token endpoint did not return a valid bearer token"),
		}
	}
	if a.cfg.GrantType == "token_exchange" {
		expected := a.cfg.RequestedTokenType
		if expected == "" {
			expected = accessTokenType
		}
		if result.IssuedTokenType != expected {
			return "", 0, &backendTokenError{
				code: outcomeBackendInvalid, err: fmt.Errorf("token endpoint returned an unexpected issued_token_type"),
			}
		}
	}
	for _, char := range result.AccessToken {
		if char <= ' ' || char == 0x7f {
			return "", 0, &backendTokenError{
				code: outcomeBackendInvalid, err: fmt.Errorf("token endpoint returned an invalid bearer token"),
			}
		}
	}
	return result.AccessToken, result.ExpiresIn, nil
}

func (a *backendAuth) addClientCredentials(form url.Values) error {
	switch a.cfg.ClientAuth {
	case "client_secret_post":
		form.Set("client_id", a.cfg.ClientID)
		form.Set("client_secret", a.secret)
	case "private_key_jwt":
		assertion, err := a.signAssertion()
		if err != nil {
			return err
		}
		form.Set("client_id", a.cfg.ClientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	}
	return nil
}

func (a *backendAuth) setBasicAuth(req *http.Request) {
	if a.cfg.ClientAuth == "client_secret_basic" {
		req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.secret))
	}
}

func (a *backendAuth) signAssertion() (string, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if a.cfg.KeyID != "" {
		header["kid"] = a.cfg.KeyID
	}
	now := time.Now().Unix()
	claims := struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		IssuedAt int64  `json:"iat"`
		ID       string `json:"jti"`
	}{
		Issuer: a.cfg.ClientID, Subject: a.cfg.ClientID,
		Audience: a.cfg.TokenURL, Expiry: now + 60, IssuedAt: now,
		ID: base64.RawURLEncoding.EncodeToString(nonce[:]),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
