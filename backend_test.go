package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func backendRecorder(t *testing.T) (*httptest.Server, chan string) {
	t.Helper()
	received := make(chan string, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server, received
}

func TestClientSecretCredentialsAndCache(t *testing.T) {
	for _, mode := range []string{"client_secret_basic", "client_secret_post"} {
		t.Run(mode, func(t *testing.T) {
			issuer := newTestIssuer(t)
			upstream, received := backendRecorder(t)
			const envName = "SEKISHO_TEST_CLIENT_SECRET"
			const secret = "s:e c/r"
			const clientID = "client:id"
			t.Setenv(envName, secret)
			var tokenRequests atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tokenRequests.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					http.Error(w, "bad form", http.StatusBadRequest)
					return
				}
				if r.Method != http.MethodPost || r.Form.Get("grant_type") != "client_credentials" ||
					r.Form.Get("scope") != "read:items write:items" ||
					r.Form.Get("resource") != "https://resource.example/api" {
					t.Errorf("unexpected token request: %v", r.Form)
				}
				if mode == "client_secret_basic" {
					username, password, ok := r.BasicAuth()
					decodedUsername, err1 := url.QueryUnescape(username)
					decodedPassword, err2 := url.QueryUnescape(password)
					if !ok || err1 != nil || err2 != nil ||
						decodedUsername != clientID || decodedPassword != secret ||
						r.Form.Get("client_secret") != "" {
						t.Errorf("unexpected Basic credentials: %q, %q, %v", username, password, ok)
					}
				} else if r.Header.Get("Authorization") != "" ||
					r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != secret {
					t.Errorf("unexpected POST credentials: %v", r.Form)
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"access_token":"backend-token","token_type":"Bearer","expires_in":3600}`)
			}))
			t.Cleanup(endpoint.Close)
			cfg := testConfig(t, issuer, upstream.URL)
			cfg.BackendAuth = BackendAuthConfig{
				GrantType: "client_credentials", TokenURL: endpoint.URL,
				ClientID: clientID, ClientAuth: mode, ClientSecretEnv: envName,
				Scope:    []string{"read:items", "write:items"},
				Resource: "https://resource.example/api",
			}
			cfg.Policy.Routes[0].Auth.Backend = "default"
			proxy := startTestProxy(t, cfg)
			incoming := issuer.sign(t, nil)
			for range 2 {
				req := authedRequest(t, http.MethodGet, proxy.URL+"/items", incoming, "")
				status, body, _ := sendRequest(t, req)
				if status != http.StatusNoContent {
					t.Fatalf("HTTP %d: %s", status, body)
				}
				if got := <-received; got != "Bearer backend-token" {
					t.Fatalf("upstream Authorization = %q", got)
				}
			}
			const concurrent = 8
			results := make(chan error, concurrent)
			for range concurrent {
				go func() {
					req, err := http.NewRequest(http.MethodGet, proxy.URL+"/items", nil)
					if err != nil {
						results <- err
						return
					}
					req.Header.Set("Authorization", "Bearer "+incoming)
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						results <- err
						return
					}
					resp.Body.Close()
					if resp.StatusCode != http.StatusNoContent {
						results <- fmt.Errorf("concurrent request returned HTTP %d", resp.StatusCode)
						return
					}
					results <- nil
				}()
			}
			for range concurrent {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
				if got := <-received; got != "Bearer backend-token" {
					t.Fatalf("concurrent upstream Authorization = %q", got)
				}
			}
			if got := tokenRequests.Load(); got != 1 {
				t.Fatalf("token endpoint called %d times, want one cached request", got)
			}
		})
	}
}

func verifyClientAssertion(compact string, publicKey *rsa.PublicKey) (map[string]any, map[string]any, error) {
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return nil, nil, fmt.Errorf("assertion is not a compact JWT")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, nil, err
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, nil, err
	}
	var header, claims map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}

func TestPrivateKeyJWT(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream, received := backendRecorder(t)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "client-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: keyBytes,
	}), 0600); err != nil {
		t.Fatal(err)
	}
	var endpoint *httptest.Server
	endpoint = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		header, claims, err := verifyClientAssertion(r.Form.Get("client_assertion"), &issuer.key.PublicKey)
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid assertion", http.StatusBadRequest)
			return
		}
		now := float64(time.Now().Unix())
		if r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("client_assertion_type") != clientAssertionType ||
			r.Form.Get("client_id") != "client-id" ||
			header["alg"] != "RS256" || header["kid"] != "client-key" ||
			claims["iss"] != "client-id" || claims["sub"] != "client-id" ||
			claims["aud"] != endpoint.URL+"/token" ||
			claims["iat"].(float64) > now || claims["exp"].(float64) < now ||
			claims["jti"] == "" {
			t.Errorf("unexpected client assertion: header=%v claims=%v form=%v", header, claims, r.Form)
		}
		fmt.Fprint(w, `{"access_token":"signed-client-token","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(endpoint.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.BackendAuth = BackendAuthConfig{
		GrantType: "client_credentials", TokenURL: endpoint.URL + "/token",
		ClientID: "client-id", ClientAuth: "private_key_jwt",
		PrivateKeyFile: keyPath, KeyID: "client-key",
	}
	cfg.Policy.Routes[0].Auth.Backend = "default"
	proxy := startTestProxy(t, cfg)
	req := authedRequest(t, http.MethodGet, proxy.URL+"/items", issuer.sign(t, nil), "")
	status, body, _ := sendRequest(t, req)
	if status != http.StatusNoContent {
		t.Fatalf("HTTP %d: %s", status, body)
	}
	if got := <-received; got != "Bearer signed-client-token" {
		t.Fatalf("upstream Authorization = %q", got)
	}
}

func TestTokenExchangeAndFailures(t *testing.T) {
	issuer := newTestIssuer(t)
	upstream, received := backendRecorder(t)
	const envName = "SEKISHO_TEST_EXCHANGE_SECRET"
	t.Setenv(envName, "exchange-secret")
	forms := make(chan url.Values, 5)
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		forms <- r.PostForm
		switch requests.Add(1) {
		case 3:
			fmt.Fprint(w, `{"access_token":"wrong-type","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:id_token"}`)
		case 4:
			http.Error(w, "secret error detail", http.StatusUnauthorized)
		case 5:
			fmt.Fprint(w, strings.Repeat("x", maxTokenResponseSize+1))
		default:
			fmt.Fprint(w, `{"access_token":"exchanged-token","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","expires_in":300}`)
		}
	}))
	t.Cleanup(endpoint.Close)
	cfg := testConfig(t, issuer, upstream.URL)
	cfg.BackendAuth = BackendAuthConfig{
		GrantType: "token_exchange", TokenURL: endpoint.URL,
		ClientID: "client-id", ClientAuth: "client_secret_post", ClientSecretEnv: envName,
		Scope: []string{"items:write"}, Audience: "backend-audience",
		Resource: "https://resource.example/api",
	}
	cfg.Policy.Routes[1].Auth.Backend = "default"
	proxy := startTestProxy(t, cfg)
	for index := range 5 {
		subject := issuer.sign(t, map[string]any{"sub": fmt.Sprintf("user-%d", index)})
		req := authedRequest(t, http.MethodPost, proxy.URL+"/items", subject, "")
		status, body, headers := sendRequest(t, req)
		if index < 2 {
			if status != http.StatusNoContent {
				t.Fatalf("exchange %d: HTTP %d: %s", index, status, body)
			}
			if got := <-received; got != "Bearer exchanged-token" {
				t.Fatalf("upstream Authorization = %q", got)
			}
		} else {
			expected := outcomeBackendInvalid
			if index == 3 {
				expected = outcomeBackendRejected
			}
			if status != http.StatusBadGateway || headers.Get("X-Proxy-Outcome") != string(expected) ||
				strings.Contains(body, "secret error detail") {
				t.Fatalf("failed exchange %d: HTTP %d (%s): %s",
					index, status, headers.Get("X-Proxy-Outcome"), body)
			}
		}
		form := <-forms
		if form.Get("grant_type") != tokenExchangeGrant ||
			form.Get("subject_token") != subject ||
			form.Get("subject_token_type") != accessTokenType ||
			form.Get("requested_token_type") != accessTokenType ||
			form.Get("audience") != "backend-audience" ||
			form.Get("resource") != "https://resource.example/api" ||
			form.Get("scope") != "items:write" {
			t.Fatalf("unexpected token exchange form: %v", form)
		}
	}
	if requests.Load() != 5 || len(received) != 0 {
		t.Fatalf("failed exchanges reached upstream or exchange was cached")
	}
}
