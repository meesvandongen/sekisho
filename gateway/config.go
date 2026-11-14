package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultHeaderBytes     = 32 << 10
	defaultBodyBytes       = 1 << 20
	defaultConcurrency     = 64
	maxConfigBytes         = 1 << 20
	maxBackendProfiles     = 64
	maxBackendCacheEntries = 1024
)

type Config struct {
	Listen                string                       `json:"listen"`
	Mode                  string                       `json:"mode"`
	AuthRequest           AuthRequestConfig            `json:"auth_request"`
	OpenAPIFile           string                       `json:"openapi_file"`
	UpstreamURL           string                       `json:"upstream_url"`
	MaxHeaderBytes        int                          `json:"max_header_bytes"`
	MaxBodyBytes          int64                        `json:"max_body_bytes"`
	MaxConcurrentRequests int                          `json:"max_concurrent_requests"`
	OIDC                  OIDCConfig                   `json:"oidc"`
	BackendAuth           BackendAuthConfig            `json:"backend_auth"`
	BackendAuthProfiles   map[string]BackendAuthConfig `json:"backend_auth_profiles"`
	Identity              IdentityConfig               `json:"identity"`
	Policy                PolicyConfig                 `json:"policy"`
	Audit                 AuditConfig                  `json:"audit"`

	configDir string
}

// AuthRequestConfig names the headers a fronting proxy (nginx auth_request,
// Traefik forwardAuth, Caddy forward_auth) uses to describe the original
// request in "auth_request" mode.
type AuthRequestConfig struct {
	MethodHeader string `json:"method_header"`
	URIHeader    string `json:"uri_header"`
}

type AuditConfig struct {
	Enabled *bool `json:"enabled"`
}

func (c AuditConfig) isEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

type OIDCConfig struct {
	Issuer     string   `json:"issuer"`
	Audience   string   `json:"audience"`
	JWKSURI    string   `json:"jwks_uri"`
	Algorithms []string `json:"algorithms"`
}

type BackendAuthConfig struct {
	GrantType          string      `json:"grant_type"`
	TokenURL           string      `json:"token_url"`
	ClientID           string      `json:"client_id"`
	ClientAuth         string      `json:"client_auth"`
	ClientSecretEnv    string      `json:"client_secret_env"`
	PrivateKeyFile     string      `json:"private_key_file"`
	KeyID              string      `json:"key_id"`
	Scope              []string    `json:"scope"`
	Audience           string      `json:"audience"`
	Resource           string      `json:"resource"`
	SubjectTokenType   string      `json:"subject_token_type"`
	RequestedTokenType string      `json:"requested_token_type"`
	Cache              CacheConfig `json:"cache"`
}

type CacheConfig struct {
	TTLSeconds int `json:"ttl_seconds"`
	MaxEntries int `json:"max_entries"`
}

type IdentityConfig struct {
	Userinfo      *UserinfoConfig      `json:"userinfo"`
	Introspection *IntrospectionConfig `json:"introspection"`
}

type UserinfoConfig struct {
	URL   string      `json:"url"`
	Cache CacheConfig `json:"cache"`
}

type IntrospectionConfig struct {
	URL             string      `json:"url"`
	ClientID        string      `json:"client_id"`
	ClientAuth      string      `json:"client_auth"`
	ClientSecretEnv string      `json:"client_secret_env"`
	PrivateKeyFile  string      `json:"private_key_file"`
	KeyID           string      `json:"key_id"`
	TokenTypeHint   string      `json:"token_type_hint"`
	Cache           CacheConfig `json:"cache"`
}

type PolicyConfig struct {
	Definitions map[string]PolicyRule `json:"definitions"`
	Routes      []RoutePolicyConfig   `json:"routes"`
	Values      map[string]any        `json:"values"`
}

type PolicyRule struct {
	CEL    string         `json:"cel"`
	File   string         `json:"file"`
	Ref    string         `json:"ref"`
	Params map[string]any `json:"params"`
	All    []PolicyRule   `json:"all"`
	Any    []PolicyRule   `json:"any"`
	Not    *PolicyRule    `json:"not"`
}

type RoutePolicyConfig struct {
	Name   string          `json:"name"`
	Match  PolicyMatcher   `json:"match"`
	Check  *PolicyRule     `json:"check"`
	Params map[string]any  `json:"params"`
	Auth   RouteAuthConfig `json:"auth"`
	OnDeny DenyConfig      `json:"on_deny"`
}

type RouteAuthConfig struct {
	Backend        string   `json:"backend"`
	RequiredScopes []string `json:"required_scopes"`
}

type DenyConfig struct {
	Response DenyResponseConfig `json:"response"`
	Log      DenyLogConfig      `json:"log"`
}

type DenyResponseConfig struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type DenyLogConfig struct {
	Reason  string `json:"reason"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return cfg, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	if _, err := decodePolicyJSON(data); err != nil {
		return cfg, fmt.Errorf("invalid config JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return cfg, fmt.Errorf("config must contain exactly one JSON object")
	}

	dir := filepath.Dir(path)
	if cfg.OpenAPIFile != "" && !filepath.IsAbs(cfg.OpenAPIFile) {
		cfg.OpenAPIFile = filepath.Join(dir, cfg.OpenAPIFile)
	}
	if cfg.BackendAuth.PrivateKeyFile != "" && !filepath.IsAbs(cfg.BackendAuth.PrivateKeyFile) {
		cfg.BackendAuth.PrivateKeyFile = filepath.Join(dir, cfg.BackendAuth.PrivateKeyFile)
	}
	for name, profile := range cfg.BackendAuthProfiles {
		if profile.PrivateKeyFile != "" && !filepath.IsAbs(profile.PrivateKeyFile) {
			profile.PrivateKeyFile = filepath.Join(dir, profile.PrivateKeyFile)
			cfg.BackendAuthProfiles[name] = profile
		}
	}
	if cfg.Identity.Introspection != nil && cfg.Identity.Introspection.PrivateKeyFile != "" &&
		!filepath.IsAbs(cfg.Identity.Introspection.PrivateKeyFile) {
		cfg.Identity.Introspection.PrivateKeyFile = filepath.Join(dir, cfg.Identity.Introspection.PrivateKeyFile)
	}
	cfg.configDir = dir
	if err := cfg.normalize(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.MaxHeaderBytes < 0 || c.MaxBodyBytes < 0 || c.MaxConcurrentRequests < 0 {
		return fmt.Errorf("request limits must be positive")
	}
	if c.MaxHeaderBytes == 0 {
		c.MaxHeaderBytes = defaultHeaderBytes
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaultBodyBytes
	}
	if c.MaxConcurrentRequests == 0 {
		c.MaxConcurrentRequests = defaultConcurrency
	}
	if c.OpenAPIFile == "" {
		return fmt.Errorf("openapi_file is required")
	}
	switch c.Mode {
	case "", "proxy":
		c.Mode = "proxy"
		if c.AuthRequest != (AuthRequestConfig{}) {
			return fmt.Errorf(`auth_request requires mode "auth_request"`)
		}
		if _, err := parseEndpoint("upstream_url", c.UpstreamURL, false); err != nil {
			return err
		}
	case "auth_request":
		if c.UpstreamURL != "" {
			return fmt.Errorf(`upstream_url is not used in mode "auth_request"; the fronting proxy forwards allowed requests`)
		}
		if c.AuthRequest.MethodHeader == "" {
			c.AuthRequest.MethodHeader = "X-Original-Method"
		}
		if c.AuthRequest.URIHeader == "" {
			c.AuthRequest.URIHeader = "X-Original-URI"
		}
		for _, name := range []string{c.AuthRequest.MethodHeader, c.AuthRequest.URIHeader} {
			if !validHeaderName(name) {
				return fmt.Errorf("auth_request header name %q is invalid", name)
			}
		}
		if http.CanonicalHeaderKey(c.AuthRequest.MethodHeader) == http.CanonicalHeaderKey(c.AuthRequest.URIHeader) {
			return fmt.Errorf("auth_request method_header and uri_header must differ")
		}
	default:
		return fmt.Errorf(`mode must be "proxy" or "auth_request"`)
	}
	if _, err := parseEndpoint("oidc.issuer", c.OIDC.Issuer, false); err != nil {
		return err
	}
	if c.OIDC.Audience == "" {
		return fmt.Errorf("oidc.audience is required")
	}
	if c.OIDC.JWKSURI != "" {
		if _, err := parseEndpoint("oidc.jwks_uri", c.OIDC.JWKSURI, true); err != nil {
			return err
		}
	}
	if len(c.OIDC.Algorithms) == 0 {
		c.OIDC.Algorithms = []string{"RS256"}
	}
	for _, algorithm := range c.OIDC.Algorithms {
		switch algorithm {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES384", "ES512", "EdDSA":
		default:
			return fmt.Errorf("unsupported oidc algorithm %q", algorithm)
		}
	}
	if err := c.BackendAuth.normalize(); err != nil {
		return fmt.Errorf("backend_auth: %w", err)
	}
	if len(c.BackendAuthProfiles) > maxBackendProfiles {
		return fmt.Errorf("backend_auth_profiles exceeds %d profiles", maxBackendProfiles)
	}
	totalCacheEntries := 0
	if c.BackendAuth.GrantType == "token_exchange" {
		totalCacheEntries += c.BackendAuth.Cache.MaxEntries
	}
	for name, profile := range c.BackendAuthProfiles {
		if name == "" || name == "default" || name == "none" || name == "forward" {
			return fmt.Errorf("backend_auth_profiles name %q is reserved or empty", name)
		}
		if err := profile.normalize(); err != nil {
			return fmt.Errorf("backend_auth_profiles[%q]: %w", name, err)
		}
		if profile.GrantType == "none" {
			return fmt.Errorf("backend_auth_profiles[%q]: use the none route selection instead", name)
		}
		if profile.GrantType == "token_exchange" {
			totalCacheEntries += profile.Cache.MaxEntries
		}
		c.BackendAuthProfiles[name] = profile
	}
	if totalCacheEntries > maxBackendCacheEntries {
		return fmt.Errorf("backend auth caches exceed %d entries in total", maxBackendCacheEntries)
	}
	if err := c.Identity.normalize(); err != nil {
		return err
	}
	return nil
}

func (c *BackendAuthConfig) normalize() error {
	if c.GrantType == "" {
		c.GrantType = "none"
	}
	if err := c.Cache.normalize(); err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	switch c.GrantType {
	case "none":
		if c.TokenURL != "" || c.ClientID != "" ||
			c.ClientAuth != "" || c.ClientSecretEnv != "" ||
			c.PrivateKeyFile != "" || c.KeyID != "" ||
			len(c.Scope) != 0 || c.Audience != "" ||
			c.Resource != "" || c.SubjectTokenType != "" ||
			c.RequestedTokenType != "" || c.Cache.TTLSeconds != 0 || c.Cache.MaxEntries != 0 {
			return fmt.Errorf("settings require a grant_type")
		}
	case "client_credentials", "token_exchange":
		if _, err := parseEndpoint("token_url", c.TokenURL, true); err != nil {
			return err
		}
		if c.ClientID == "" {
			return fmt.Errorf("client_id is required")
		}
		switch c.ClientAuth {
		case "client_secret_basic", "client_secret_post":
			if c.ClientSecretEnv == "" || c.PrivateKeyFile != "" {
				return fmt.Errorf("%s requires client_secret_env and no private_key_file", c.ClientAuth)
			}
		case "private_key_jwt":
			if c.PrivateKeyFile == "" || c.ClientSecretEnv != "" {
				return fmt.Errorf("private_key_jwt requires private_key_file and no client_secret_env")
			}
		default:
			return fmt.Errorf("unsupported client_auth %q", c.ClientAuth)
		}
		if c.GrantType != "token_exchange" && (c.Cache.TTLSeconds != 0 || c.Cache.MaxEntries != 0) {
			return fmt.Errorf("cache is only configurable for token_exchange")
		}
	default:
		return fmt.Errorf("unsupported grant_type %q", c.GrantType)
	}
	return nil
}

func (c *CacheConfig) normalize() error {
	if c.TTLSeconds < 0 || c.TTLSeconds > 300 || c.MaxEntries < 0 || c.MaxEntries > 256 {
		return fmt.Errorf("ttl_seconds must be 0..300 and max_entries must be 0..256")
	}
	if c.TTLSeconds == 0 && c.MaxEntries != 0 {
		return fmt.Errorf("max_entries requires ttl_seconds")
	}
	if c.TTLSeconds > 0 && c.MaxEntries == 0 {
		c.MaxEntries = 128
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if char > 0x7e || char <= ' ' || strings.ContainsRune("\"(),/:;<=>?@[\\]{}", char) {
			return false
		}
	}
	return true
}

func parseEndpoint(name, raw string, allowQuery bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL without userinfo or a fragment", name)
	}
	if !allowQuery && u.RawQuery != "" {
		return nil, fmt.Errorf("%s must not contain a query", name)
	}
	return u, nil
}
