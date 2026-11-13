package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/interpreter"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkin/kin-openapi/routers"
)

type requestInputs struct {
	w            http.ResponseWriter
	r            *http.Request
	route        *routers.Route
	binding      *compiledRoute
	pathParams   map[string]string
	token        *oidc.IDToken
	rawToken     string
	values       map[string]any
	sources      *identitySources
	maxBodyBytes int64

	fixtureClaims        map[string]any
	fixtureUserinfo      map[string]any
	fixtureIntrospection map[string]any
	offline              bool

	failure             *policyFailure
	claims              map[string]any
	claimsLoaded        bool
	body                []byte
	bodyLoaded          bool
	jsonBody            any
	jsonLoaded          bool
	headers             map[string][]string
	headersLoaded       bool
	query               map[string][]string
	queryLoaded         bool
	userinfo            map[string]any
	userinfoLoaded      bool
	introspection       map[string]any
	introspectionLoaded bool
}

type policyActivation struct {
	inputs *requestInputs
	params map[string]any
}

var _ interpreter.Activation = (*policyActivation)(nil)

func (a *policyActivation) Parent() interpreter.Activation { return nil }

func (a *policyActivation) ResolveName(name string) (any, bool) {
	if name == "params" {
		if a.params == nil {
			return map[string]any{}, true
		}
		return a.params, true
	}
	return a.inputs.resolve(name)
}

func (i *requestInputs) resolve(name string) (any, bool) {
	if i.failure != nil {
		return types.NewErr("policy input unavailable"), true
	}
	switch name {
	case "claims":
		claims, failure := i.claimsValue()
		if failure != nil {
			return i.fail(failure), true
		}
		return claims, true
	case "body", "body_bytes", "body_text":
		data, failure := i.bodyValue()
		if failure != nil {
			return i.fail(failure), true
		}
		switch name {
		case "body_bytes":
			return data, true
		case "body_text":
			if !utf8.Valid(data) {
				return i.fail(&policyFailure{
					status: http.StatusBadRequest, code: outcomeInvalidBodyText,
					err: fmt.Errorf("body_text requires valid UTF-8"),
				}), true
			}
			return string(data), true
		}
		if !i.jsonLoaded {
			i.jsonLoaded = true
			var status int
			var err error
			i.jsonBody, status, err = parsePolicyJSON(data, i.r.Header.Get("Content-Type"))
			if err != nil {
				code := outcomeInvalidJSON
				if status == http.StatusUnsupportedMediaType {
					code = outcomeUnsupportedMedia
				}
				return i.fail(&policyFailure{status: status, code: code, err: err}), true
			}
		}
		return i.jsonBody, true
	case "headers":
		if !i.headersLoaded {
			i.headersLoaded = true
			i.headers = make(map[string][]string, len(i.r.Header))
			for name, values := range i.r.Header {
				key := strings.ToLower(name)
				i.headers[key] = append(i.headers[key], values...)
			}
		}
		return i.headers, true
	case "query":
		if !i.queryLoaded {
			i.queryLoaded = true
			parsed, err := url.ParseQuery(i.r.URL.RawQuery)
			if err != nil {
				return i.fail(&policyFailure{
					status: http.StatusBadRequest, code: outcomeInvalidQuery, err: err,
				}), true
			}
			i.query = map[string][]string(parsed)
		}
		return i.query, true
	case "path_params":
		if i.pathParams == nil {
			return map[string]string{}, true
		}
		return i.pathParams, true
	case "method":
		return i.r.Method, true
	case "path":
		return i.r.URL.Path, true
	case "host":
		return i.r.Host, true
	case "operation":
		return i.binding.operation, true
	case "operation_id":
		return i.route.Operation.OperationID, true
	case "config":
		if i.values == nil {
			return map[string]any{}, true
		}
		return i.values, true
	case "userinfo":
		if !i.userinfoLoaded {
			i.userinfoLoaded = true
			if i.offline {
				if i.fixtureUserinfo == nil {
					return i.fail(missingFixture("userinfo")), true
				}
				i.userinfo = i.fixtureUserinfo
				claims, failure := i.claimsValue()
				if failure != nil {
					return i.fail(failure), true
				}
				subject, _ := claims["sub"].(string)
				if failure := validateUserinfo(i.userinfo, subject); failure != nil {
					return i.fail(failure), true
				}
			} else {
				var failure *policyFailure
				i.userinfo, failure = i.sources.userinfo.get(
					i.r.Context(), i.rawToken, i.token.Subject, i.token.Expiry,
				)
				if failure != nil {
					return i.fail(failure), true
				}
			}
		}
		return i.userinfo, true
	case "introspection":
		if !i.introspectionLoaded {
			i.introspectionLoaded = true
			if i.offline {
				if i.fixtureIntrospection == nil {
					return i.fail(missingFixture("introspection")), true
				}
				i.introspection = i.fixtureIntrospection
				claims, failure := i.claimsValue()
				if failure != nil {
					return i.fail(failure), true
				}
				subject, _ := claims["sub"].(string)
				if _, failure := validateIntrospection(i.introspection, subject); failure != nil {
					return i.fail(failure), true
				}
			} else {
				var failure *policyFailure
				i.introspection, failure = i.sources.introspection.get(
					i.r.Context(), i.rawToken, i.token.Subject, i.token.Expiry,
				)
				if failure != nil {
					return i.fail(failure), true
				}
			}
		}
		return i.introspection, true
	default:
		return nil, false
	}
}

func missingFixture(name string) *policyFailure {
	return &policyFailure{
		status: http.StatusForbidden, code: outcomePolicyError,
		err: fmt.Errorf("fixture requires %s value", name),
	}
}

func (i *requestInputs) fail(failure *policyFailure) any {
	if i.failure == nil {
		i.failure = failure
	}
	return types.NewErr("policy input unavailable")
}

func (i *requestInputs) claimsValue() (map[string]any, *policyFailure) {
	if i.claimsLoaded {
		return i.claims, nil
	}
	i.claimsLoaded = true
	if i.offline {
		if i.fixtureClaims == nil {
			i.claims = map[string]any{}
		} else {
			i.claims = i.fixtureClaims
		}
		return i.claims, nil
	}
	if err := i.token.Claims(&i.claims); err != nil {
		return nil, &policyFailure{status: http.StatusUnauthorized, code: outcomeClaimsInvalid, err: err}
	}
	return i.claims, nil
}

func (i *requestInputs) bodyValue() ([]byte, *policyFailure) {
	if i.bodyLoaded {
		return i.body, nil
	}
	i.bodyLoaded = true
	data, status, err := readPolicyBody(i.w, i.r, i.maxBodyBytes)
	if err != nil {
		code := outcomeBodyReadError
		if status == http.StatusRequestEntityTooLarge {
			code = outcomeBodyTooLarge
		}
		return nil, &policyFailure{status: status, code: code, err: err}
	}
	i.body = data
	return data, nil
}

func (i *requestInputs) requireScopes(scopes []string) *policyFailure {
	if len(scopes) == 0 {
		return nil
	}
	claims, failure := i.claimsValue()
	if failure != nil {
		return failure
	}
	available := make(map[string]bool)
	if raw, ok := claims["scope"]; ok {
		value, ok := raw.(string)
		if !ok {
			return &policyFailure{status: http.StatusUnauthorized, code: outcomeClaimsInvalid,
				err: fmt.Errorf("scope claim must be a string")}
		}
		for _, scope := range strings.Fields(value) {
			available[scope] = true
		}
	}
	if raw, ok := claims["scp"]; ok {
		switch values := raw.(type) {
		case string:
			for _, scope := range strings.Fields(values) {
				available[scope] = true
			}
		case []any:
			for _, item := range values {
				scope, ok := item.(string)
				if !ok {
					return &policyFailure{status: http.StatusUnauthorized, code: outcomeClaimsInvalid,
						err: fmt.Errorf("scp claim contains a non-string scope")}
				}
				available[scope] = true
			}
		default:
			return &policyFailure{status: http.StatusUnauthorized, code: outcomeClaimsInvalid,
				err: fmt.Errorf("scp claim must be a string or array")}
		}
	}
	for _, scope := range scopes {
		if !available[scope] {
			return &policyFailure{status: http.StatusForbidden, code: outcomeInsufficientScope,
				err: fmt.Errorf("required scope is missing")}
		}
	}
	return nil
}
