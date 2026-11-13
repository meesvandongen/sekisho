package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

const maxIdentityResponseBytes = 16 << 10

type identitySources struct {
	userinfo      *userinfoSource
	introspection *introspectionSource
}

type userinfoSource struct {
	config UserinfoConfig
	client *http.Client
	cache  *boundedCache[map[string]any]
	group  singleflight.Group
}

type introspectionSource struct {
	config IntrospectionConfig
	client *http.Client
	auth   *backendAuth
	cache  *boundedCache[map[string]any]
	group  singleflight.Group
}

func (cfg *IdentityConfig) normalize() error {
	if cfg.Userinfo != nil {
		if _, err := parseEndpoint("identity.userinfo.url", cfg.Userinfo.URL, false); err != nil {
			return err
		}
		if err := cfg.Userinfo.Cache.normalize(); err != nil {
			return fmt.Errorf("identity.userinfo.cache: %w", err)
		}
	}
	if cfg.Introspection != nil {
		value := cfg.Introspection
		if _, err := parseEndpoint("identity.introspection.url", value.URL, false); err != nil {
			return err
		}
		if err := value.Cache.normalize(); err != nil {
			return fmt.Errorf("identity.introspection.cache: %w", err)
		}
		if len(value.TokenTypeHint) > 64 || strings.ContainsAny(value.TokenTypeHint, " \t\r\n") {
			return fmt.Errorf("identity.introspection.token_type_hint must be at most 64 bytes without whitespace")
		}
		auth := value.credentials()
		if err := auth.normalize(); err != nil {
			return fmt.Errorf("identity.introspection: %w", err)
		}
	}
	return nil
}

func (cfg IntrospectionConfig) credentials() BackendAuthConfig {
	return BackendAuthConfig{
		GrantType: "client_credentials", TokenURL: cfg.URL,
		ClientID: cfg.ClientID, ClientAuth: cfg.ClientAuth,
		ClientSecretEnv: cfg.ClientSecretEnv, PrivateKeyFile: cfg.PrivateKeyFile, KeyID: cfg.KeyID,
	}
}

func newIdentitySources(cfg IdentityConfig, client *http.Client, needUserinfo, needIntrospection bool) (*identitySources, error) {
	sources := &identitySources{}
	if needUserinfo {
		sources.userinfo = &userinfoSource{config: *cfg.Userinfo, client: client}
		if cfg.Userinfo.Cache.TTLSeconds > 0 {
			sources.userinfo.cache = newBoundedCache[map[string]any](cfg.Userinfo.Cache.MaxEntries)
		}
	}
	if needIntrospection {
		auth, err := newBackendAuth(cfg.Introspection.credentials(), client)
		if err != nil {
			return nil, fmt.Errorf("configure introspection credentials: %w", err)
		}
		sources.introspection = &introspectionSource{config: *cfg.Introspection, client: client, auth: auth}
		if cfg.Introspection.Cache.TTLSeconds > 0 {
			sources.introspection.cache = newBoundedCache[map[string]any](cfg.Introspection.Cache.MaxEntries)
		}
	}
	return sources, nil
}

func (s *userinfoSource) get(ctx context.Context, rawToken, subject string, tokenExpiry time.Time) (map[string]any, *policyFailure) {
	key := sha256.Sum256([]byte(rawToken))
	if s.cache != nil {
		if cached, ok := s.cache.get(key); ok {
			return cached, nil
		}
	}
	result := s.group.DoChan(string(key[:]), func() (any, error) {
		if s.cache != nil {
			if cached, ok := s.cache.get(key); ok {
				return cached, nil
			}
		}
		data, failure := s.fetch(ctx, rawToken, subject)
		if failure != nil {
			return nil, failure
		}
		if s.cache != nil {
			s.cache.put(key, data, cacheUntil(s.config.Cache.TTLSeconds, tokenExpiry))
		}
		return data, nil
	})
	select {
	case <-ctx.Done():
		return nil, &policyFailure{status: http.StatusBadGateway, code: outcomeUserinfoUnavailable, err: ctx.Err()}
	case resolved := <-result:
		if resolved.Err != nil {
			return nil, identityFailure(resolved.Err, outcomeUserinfoUnavailable)
		}
		return resolved.Val.(map[string]any), nil
	}
}

func (s *userinfoSource) fetch(ctx context.Context, rawToken, subject string) (map[string]any, *policyFailure) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.URL, nil)
	if err != nil {
		return nil, &policyFailure{status: http.StatusBadGateway, code: outcomeUserinfoUnavailable, err: err}
	}
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Accept", "application/json")
	data, failure := identityRequest(s.client, req, outcomeUserinfoUnavailable, outcomeUserinfoInvalid)
	if failure != nil {
		return nil, failure
	}
	value, failure := identityJSON(data, outcomeUserinfoInvalid)
	if failure != nil {
		return nil, failure
	}
	if failure := validateUserinfo(value, subject); failure != nil {
		return nil, failure
	}
	return value, nil
}

func validateUserinfo(value map[string]any, subject string) *policyFailure {
	if sub, ok := value["sub"].(string); !ok || sub == "" || sub != subject {
		return &policyFailure{
			status: http.StatusUnauthorized, code: outcomeUserinfoMismatch,
			err: fmt.Errorf("userinfo subject does not match verified token"),
		}
	}
	return nil
}

func (s *introspectionSource) get(
	ctx context.Context, rawToken, subject string, tokenExpiry time.Time,
) (map[string]any, *policyFailure) {
	key := sha256.Sum256([]byte(rawToken))
	if s.cache != nil {
		if cached, ok := s.cache.get(key); ok {
			return cached, nil
		}
	}
	result := s.group.DoChan(string(key[:]), func() (any, error) {
		if s.cache != nil {
			if cached, ok := s.cache.get(key); ok {
				return cached, nil
			}
		}
		data, expiry, failure := s.fetch(ctx, rawToken, subject)
		if failure != nil {
			return nil, failure
		}
		if s.cache != nil {
			s.cache.put(key, data, cacheUntil(s.config.Cache.TTLSeconds, tokenExpiry, expiry))
		}
		return data, nil
	})
	select {
	case <-ctx.Done():
		return nil, &policyFailure{status: http.StatusBadGateway, code: outcomeIntrospectionUnavailable, err: ctx.Err()}
	case resolved := <-result:
		if resolved.Err != nil {
			return nil, identityFailure(resolved.Err, outcomeIntrospectionUnavailable)
		}
		return resolved.Val.(map[string]any), nil
	}
}

func (s *introspectionSource) fetch(
	ctx context.Context, rawToken, subject string,
) (map[string]any, time.Time, *policyFailure) {
	form := url.Values{"token": {rawToken}}
	if s.config.TokenTypeHint != "" {
		form.Set("token_type_hint", s.config.TokenTypeHint)
	}
	if err := s.auth.addClientCredentials(form); err != nil {
		return nil, time.Time{}, &policyFailure{
			status: http.StatusBadGateway, code: outcomeIntrospectionUnavailable, err: err,
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, time.Time{}, &policyFailure{
			status: http.StatusBadGateway, code: outcomeIntrospectionUnavailable, err: err,
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	s.auth.setBasicAuth(req)
	data, failure := identityRequest(s.client, req, outcomeIntrospectionUnavailable, outcomeIntrospectionInvalid)
	if failure != nil {
		return nil, time.Time{}, failure
	}
	value, failure := identityJSON(data, outcomeIntrospectionInvalid)
	if failure != nil {
		return nil, time.Time{}, failure
	}
	expiry, failure := validateIntrospection(value, subject)
	return value, expiry, failure
}

func validateIntrospection(value map[string]any, subject string) (time.Time, *policyFailure) {
	active, ok := value["active"].(bool)
	if !ok {
		return time.Time{}, &policyFailure{
			status: http.StatusBadGateway, code: outcomeIntrospectionInvalid,
			err: fmt.Errorf("introspection response missing active boolean"),
		}
	}
	if !active {
		return time.Time{}, &policyFailure{
			status: http.StatusUnauthorized, code: outcomeTokenInactive,
			err: fmt.Errorf("introspection reports inactive token"),
		}
	}
	if remoteSubject, exists := value["sub"]; exists && remoteSubject != subject {
		return time.Time{}, &policyFailure{
			status: http.StatusUnauthorized, code: outcomeIntrospectionMismatch,
			err: fmt.Errorf("introspection subject does not match verified token"),
		}
	}
	var expiry time.Time
	if rawExpiry, exists := value["exp"]; exists {
		seconds, ok := rawExpiry.(float64)
		if !ok || seconds != math.Trunc(seconds) || seconds < 0 {
			return time.Time{}, &policyFailure{
				status: http.StatusBadGateway, code: outcomeIntrospectionInvalid,
				err: fmt.Errorf("invalid introspection expiry"),
			}
		}
		expiry = time.Unix(int64(seconds), 0)
		if !time.Now().Before(expiry) {
			return time.Time{}, &policyFailure{
				status: http.StatusUnauthorized, code: outcomeTokenInactive,
				err: fmt.Errorf("introspection reports expired token"),
			}
		}
	}
	return expiry, nil
}

func identityRequest(client *http.Client, req *http.Request, unavailable, invalid outcomeCode) ([]byte, *policyFailure) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, &policyFailure{status: http.StatusBadGateway, code: unavailable, err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &policyFailure{
			status: http.StatusBadGateway, code: unavailable, dependencyStatus: resp.StatusCode,
			err: fmt.Errorf("identity endpoint returned HTTP %d", resp.StatusCode),
		}
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, &policyFailure{
			status: http.StatusBadGateway, code: invalid, err: fmt.Errorf("identity endpoint returned non-JSON"),
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIdentityResponseBytes+1))
	if err != nil || len(data) > maxIdentityResponseBytes {
		return nil, &policyFailure{
			status: http.StatusBadGateway, code: invalid, err: fmt.Errorf("identity response invalid or too large"),
		}
	}
	return data, nil
}

func identityJSON(data []byte, code outcomeCode) (map[string]any, *policyFailure) {
	decoded, err := decodePolicyJSON(data)
	if err != nil {
		return nil, &policyFailure{status: http.StatusBadGateway, code: code, err: err}
	}
	value, ok := decoded.(map[string]any)
	if !ok {
		return nil, &policyFailure{
			status: http.StatusBadGateway, code: code, err: fmt.Errorf("identity response must be a JSON object"),
		}
	}
	return value, nil
}

func identityFailure(err error, fallback outcomeCode) *policyFailure {
	var failure *policyFailure
	if errors.As(err, &failure) {
		return failure
	}
	return &policyFailure{status: http.StatusBadGateway, code: fallback, err: err}
}

func (f *policyFailure) Error() string { return f.err.Error() }
