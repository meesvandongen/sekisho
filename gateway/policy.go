package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
)

const (
	maxPolicyCost      = 10_000
	maxPolicyNodes     = 4096
	maxPolicyEvalNodes = 256
	maxPolicyDepth     = 16
	maxPolicyFileBytes = 64 << 10
	maxOperationBytes  = 256 << 10
	maxOperationsTotal = 8 << 20
	maxJSONDepth       = 64
	maxJSONValues      = 20_000
)

type compiledPolicy struct {
	program cel.Program
	uses    map[string]bool
}

type policyFailure struct {
	status           int
	code             outcomeCode
	err              error
	dependencyStatus int
}

type policySet struct {
	routes map[routeKey]*compiledRoute
	order  []*compiledRoute
	values map[string]any
}

type routeKey struct {
	method string
	path   string
}

// compiledBinding is one entry of policy.routes after compilation.
type compiledBinding struct {
	index          int
	name           string
	rule           *compiledRule
	params         map[string]any
	backendName    string
	requiredScopes []string
	deny           DenyConfig
	operations     operationSet
}

func (b *compiledBinding) label() string {
	if b.name != "" {
		return fmt.Sprintf("routes[%d] %s", b.index, b.name)
	}
	return fmt.Sprintf("routes[%d]", b.index)
}

// compiledRoute is the effective policy for one OpenAPI operation: every
// matching binding in configuration order plus the resolved backend.
type compiledRoute struct {
	key            routeKey
	operationID    string
	bindings       []*compiledBinding
	backendName    string
	backendBinding *compiledBinding
	backend        *backendAuth
	operation      map[string]any
}

// owner is the binding reported in audit events when no binding decided a denial.
func (r *compiledRoute) owner() string {
	return r.backendBinding.name
}

type routeDecision struct {
	binding *compiledBinding
	failure *policyFailure
	denied  bool
	scopes  bool
}

// decide checks every matching binding's scopes, then every check in
// configuration order, stopping at the first failure or denial.
func (r *compiledRoute) decide(inputs *requestInputs) routeDecision {
	for _, binding := range r.bindings {
		if failure := inputs.requireScopes(binding.requiredScopes); failure != nil {
			return routeDecision{binding: binding, failure: failure, scopes: true}
		}
	}
	for _, binding := range r.bindings {
		if binding.rule == nil {
			continue
		}
		allowed, failure := binding.rule.evaluate(inputs, binding.params)
		if failure != nil {
			return routeDecision{binding: binding, failure: failure}
		}
		if !allowed {
			return routeDecision{binding: binding, denied: true}
		}
	}
	return routeDecision{}
}

type compiledRule struct {
	kind     string
	expr     *compiledPolicy
	children []*compiledRule
	ref      *compiledRule
	params   map[string]any
}

type policyCompiler struct {
	env         *cel.Env
	definitions map[string]PolicyRule
	compiled    map[string]*compiledRule
	visiting    map[string]bool
	expressions map[string]*compiledPolicy
	baseDir     string
	count       int
}

func compilePolicies(cfg Config, spec *openapi3.T) (*policySet, error) {
	env, err := cel.NewEnv(
		cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("body", cel.DynType),
		cel.Variable("body_bytes", cel.BytesType),
		cel.Variable("body_text", cel.StringType),
		cel.Variable("headers", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("query", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("path_params", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("method", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("host", cel.StringType),
		cel.Variable("operation", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("operation_id", cel.StringType),
		cel.Variable("config", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("userinfo", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("introspection", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("create policy environment: %w", err)
	}
	compiler := &policyCompiler{
		env: env, definitions: cfg.Policy.Definitions, compiled: make(map[string]*compiledRule),
		visiting: make(map[string]bool), expressions: make(map[string]*compiledPolicy),
		baseDir: cfg.configDir,
	}
	names := make([]string, 0, len(cfg.Policy.Definitions))
	for name := range cfg.Policy.Definitions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !validPolicyName(name) {
			return nil, fmt.Errorf("invalid policy definition name %q", name)
		}
		_, err := compiler.named(name, 0)
		if err != nil {
			return nil, err
		}
	}

	index, specOperations, err := indexOperations(spec)
	if err != nil {
		return nil, err
	}
	matchers := &matcherCompiler{index: index}
	bindings := make([]*compiledBinding, 0, len(cfg.Policy.Routes))
	for position, route := range cfg.Policy.Routes {
		binding, err := compileBinding(cfg, compiler, matchers, position, route)
		if err != nil {
			return nil, fmt.Errorf("policy.routes[%d]: %w", position, err)
		}
		bindings = append(bindings, binding)
	}

	result := &policySet{routes: make(map[routeKey]*compiledRoute, len(index.operations)), values: cfg.Policy.Values}
	var unchecked, unresolved []string
	operationBytes := 0
	for position, info := range index.operations {
		route := &compiledRoute{key: info.key, operationID: info.id}
		checked, usesOperation := false, false
		for _, binding := range bindings {
			if !binding.operations.contains(position) {
				continue
			}
			route.bindings = append(route.bindings, binding)
			if binding.rule != nil {
				checked = true
				usesOperation = usesOperation || binding.rule.uses("operation")
			}
		}
		label := info.key.method + " " + info.key.path
		if !checked {
			unchecked = append(unchecked, label)
			continue
		}
		if err := route.resolveBackend(); err != nil {
			unresolved = append(unresolved, label+": "+err.Error())
			continue
		}
		if usesOperation {
			serialized, err := json.Marshal(specOperations[position])
			if err != nil || len(serialized) > maxOperationBytes {
				return nil, fmt.Errorf("%s: OpenAPI operation exceeds policy limit", label)
			}
			operationBytes += len(serialized)
			if operationBytes > maxOperationsTotal {
				return nil, fmt.Errorf("OpenAPI operation metadata exceeds total policy limit")
			}
			if err := json.Unmarshal(serialized, &route.operation); err != nil {
				return nil, fmt.Errorf("%s: decode OpenAPI operation: %w", label, err)
			}
		}
		result.routes[info.key] = route
		result.order = append(result.order, route)
	}
	if len(unchecked) > 0 {
		return nil, fmt.Errorf("OpenAPI operations not matched by any binding with a check: %s",
			strings.Join(unchecked, ", "))
	}
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("cannot resolve backend auth: %s", strings.Join(unresolved, "; "))
	}
	return result, nil
}

func indexOperations(spec *openapi3.T) (*operationIndex, []*openapi3.Operation, error) {
	index := &operationIndex{byID: make(map[string]int), paths: make(map[string]bool), tags: make(map[string]bool)}
	var operations []*openapi3.Operation
	paths := spec.Paths.InMatchingOrder()
	sort.Strings(paths)
	for _, path := range paths {
		pathItem := spec.Paths.Value(path)
		methods := make([]string, 0)
		for method := range pathItem.Operations() {
			methods = append(methods, method)
		}
		sort.Strings(methods)
		for _, method := range methods {
			operation := pathItem.GetOperation(method)
			info := operationInfo{key: routeKey{method, path}, id: operation.OperationID, tags: operation.Tags}
			if operation.OperationID != "" {
				if _, exists := index.byID[operation.OperationID]; exists {
					return nil, nil, fmt.Errorf("duplicate OpenAPI operationId %q", operation.OperationID)
				}
				index.byID[operation.OperationID] = len(index.operations)
			}
			if len(operation.Extensions) > 0 {
				normalized, err := normalizeJSONValue(operation.Extensions)
				if err != nil {
					return nil, nil, fmt.Errorf("%s %s: OpenAPI extensions: %w", method, path, err)
				}
				info.extensions, _ = normalized.(map[string]any)
			}
			for _, tag := range operation.Tags {
				index.tags[tag] = true
			}
			index.paths[path] = true
			index.operations = append(index.operations, info)
			operations = append(operations, operation)
		}
	}
	return index, operations, nil
}

func compileBinding(
	cfg Config, compiler *policyCompiler, matchers *matcherCompiler, position int, route RoutePolicyConfig,
) (*compiledBinding, error) {
	if route.Name != "" && !validPolicyName(route.Name) {
		return nil, fmt.Errorf("invalid name %q", route.Name)
	}
	selected, err := matchers.selectOperations(route.Match, 0)
	if err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if selected.count() == 0 {
		return nil, fmt.Errorf("match selects no OpenAPI operations")
	}
	if route.Check == nil && route.Auth.Backend == "" && len(route.Auth.RequiredScopes) == 0 {
		return nil, fmt.Errorf("binding needs a check, auth.backend or auth.required_scopes")
	}
	if route.Check == nil && (len(route.Params) > 0 || !reflect.DeepEqual(route.OnDeny, DenyConfig{})) {
		return nil, fmt.Errorf("params and on_deny require a check")
	}
	if err := route.OnDeny.normalize(); err != nil {
		return nil, fmt.Errorf("on_deny: %w", err)
	}
	if err := route.Auth.validate(cfg.BackendAuth, cfg.BackendAuthProfiles); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	binding := &compiledBinding{
		index: position, name: route.Name, params: route.Params, backendName: route.Auth.Backend,
		requiredScopes: route.Auth.RequiredScopes, deny: route.OnDeny, operations: selected,
	}
	if route.Check == nil {
		return binding, nil
	}
	binding.rule, err = compiler.compile(*route.Check, 0)
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	expanded := 0
	if err := binding.rule.validateExpansion(&expanded, 0); err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	if binding.rule.uses("userinfo") && cfg.Identity.Userinfo == nil {
		return nil, fmt.Errorf("check uses unconfigured userinfo")
	}
	if binding.rule.uses("introspection") && cfg.Identity.Introspection == nil {
		return nil, fmt.Errorf("check uses unconfigured introspection")
	}
	return binding, nil
}

// resolveBackend picks the backend from the narrowest matching bindings that
// set one: those whose selected operations contain no other candidate's
// selection. All of those must agree.
func (r *compiledRoute) resolveBackend() error {
	var candidates []*compiledBinding
	for _, binding := range r.bindings {
		if binding.backendName != "" {
			candidates = append(candidates, binding)
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no matching binding sets auth.backend")
	}
	var narrowest []*compiledBinding
	for _, candidate := range candidates {
		minimal := true
		for _, other := range candidates {
			if other != candidate && other.operations.subsetOf(candidate.operations) &&
				!candidate.operations.subsetOf(other.operations) {
				minimal = false
				break
			}
		}
		if minimal {
			narrowest = append(narrowest, candidate)
		}
	}
	for _, candidate := range narrowest[1:] {
		if candidate.backendName != narrowest[0].backendName {
			return fmt.Errorf("%s selects %q but %s selects %q and neither is narrower; "+
				"add a binding that matches exactly the overlapping operations to choose one",
				narrowest[0].label(), narrowest[0].backendName, candidate.label(), candidate.backendName)
		}
	}
	r.backendName = narrowest[0].backendName
	r.backendBinding = narrowest[0]
	return nil
}

func (a RouteAuthConfig) validate(defaultBackend BackendAuthConfig, profiles map[string]BackendAuthConfig) error {
	switch a.Backend {
	case "", "none", "forward":
	case "default":
		if defaultBackend.GrantType == "none" {
			return fmt.Errorf("backend default is not configured; select none explicitly")
		}
	default:
		if _, ok := profiles[a.Backend]; !ok {
			return fmt.Errorf("unknown backend auth profile %q", a.Backend)
		}
	}
	seen := make(map[string]bool, len(a.RequiredScopes))
	for _, scope := range a.RequiredScopes {
		if scope == "" || len(scope) > 128 || strings.ContainsAny(scope, " \t\r\n") || seen[scope] {
			return fmt.Errorf("invalid or duplicate required scope %q", scope)
		}
		seen[scope] = true
	}
	return nil
}

func (d *DenyConfig) normalize() error {
	if d.Response.Status == 0 {
		d.Response.Status = http.StatusForbidden
	}
	switch d.Response.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
	default:
		return fmt.Errorf("response.status must be 401, 403, or 404")
	}
	if d.Response.Code == "" {
		d.Response.Code = string(outcomePolicyDenied)
	}
	if !validPolicyName(d.Response.Code) {
		return fmt.Errorf("invalid response.code %q", d.Response.Code)
	}
	if d.Response.Code == string(outcomeForwarded) {
		return fmt.Errorf("response.code cannot report a denied request as forwarded")
	}
	if len(d.Response.Detail) > 256 || !utf8.ValidString(d.Response.Detail) ||
		strings.ContainsAny(d.Response.Detail, "\r\n") {
		return fmt.Errorf("response.detail must be at most 256 UTF-8 bytes without newlines")
	}
	if d.Log.Level == "" {
		d.Log.Level = "info"
	}
	switch d.Log.Level {
	case "info", "warn", "error":
	default:
		return fmt.Errorf("log.level must be info, warn, or error")
	}
	if d.Log.Reason != "" && !validPolicyName(d.Log.Reason) {
		return fmt.Errorf("invalid log.reason %q", d.Log.Reason)
	}
	if len(d.Log.Message) > 256 || !utf8.ValidString(d.Log.Message) ||
		strings.ContainsAny(d.Log.Message, "\r\n") {
		return fmt.Errorf("log.message must be at most 256 UTF-8 bytes without newlines")
	}
	return nil
}

func validPolicyName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for index, char := range name {
		if (char >= 'a' && char <= 'z') || (index > 0 && ((char >= '0' && char <= '9') || char == '_')) {
			continue
		}
		return false
	}
	return true
}

func (c *policyCompiler) named(name string, depth int) (*compiledRule, error) {
	rule, ok := c.definitions[name]
	if !ok {
		return nil, fmt.Errorf("unknown policy reference %q", name)
	}
	if c.visiting[name] {
		return nil, fmt.Errorf("cycle in policy reference %q", name)
	}
	if compiled := c.compiled[name]; compiled != nil {
		return compiled, nil
	}
	c.visiting[name] = true
	result, err := c.compile(rule, depth+1)
	delete(c.visiting, name)
	if err != nil {
		return nil, fmt.Errorf("policy definition %q: %w", name, err)
	}
	c.compiled[name] = result
	return result, nil
}

func (c *policyCompiler) compile(rule PolicyRule, depth int) (*compiledRule, error) {
	c.count++
	if c.count > maxPolicyNodes || depth > maxPolicyDepth {
		return nil, fmt.Errorf("policy graph exceeds depth or node limit")
	}
	options := 0
	for _, configured := range []bool{
		rule.CEL != "", rule.File != "", rule.Ref != "", rule.All != nil,
		rule.Any != nil, rule.Not != nil,
	} {
		if configured {
			options++
		}
	}
	if options != 1 || (len(rule.Params) > 0 && rule.Ref == "") {
		return nil, fmt.Errorf("rule needs exactly one of cel, file, ref, all, any, or not; params require ref")
	}
	result := &compiledRule{params: rule.Params}
	switch {
	case rule.CEL != "" || rule.File != "":
		expression := rule.CEL
		if rule.File != "" {
			path := rule.File
			if !filepath.IsAbs(path) {
				path = filepath.Join(c.baseDir, path)
			}
			file, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("open policy file %q: %w", rule.File, err)
			}
			data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileBytes+1))
			closeErr := file.Close()
			if err != nil {
				return nil, fmt.Errorf("read policy file %q: %w", rule.File, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("close policy file %q: %w", rule.File, closeErr)
			}
			if len(data) > maxPolicyFileBytes || !utf8.Valid(data) {
				return nil, fmt.Errorf("policy file %q is too large or invalid UTF-8", rule.File)
			}
			expression = string(data)
		}
		if strings.TrimSpace(expression) == "" {
			return nil, fmt.Errorf("empty CEL policy")
		}
		result.kind = "cel"
		if result.expr = c.expressions[expression]; result.expr == nil {
			var err error
			result.expr, err = compilePolicy(c.env, expression)
			if err != nil {
				return nil, fmt.Errorf("compile CEL: %w", err)
			}
			c.expressions[expression] = result.expr
		}
	case rule.Ref != "":
		result.kind = "ref"
		compiled, err := c.named(rule.Ref, depth)
		if err != nil {
			return nil, err
		}
		result.ref = compiled
	case rule.All != nil || rule.Any != nil:
		children := rule.All
		result.kind = "all"
		if rule.Any != nil {
			children = rule.Any
			result.kind = "any"
		}
		if len(children) == 0 {
			return nil, fmt.Errorf("%s requires at least one child", result.kind)
		}
		for _, child := range children {
			compiled, err := c.compile(child, depth+1)
			if err != nil {
				return nil, err
			}
			result.children = append(result.children, compiled)
		}
	case rule.Not != nil:
		result.kind = "not"
		compiled, err := c.compile(*rule.Not, depth+1)
		if err != nil {
			return nil, err
		}
		result.children = []*compiledRule{compiled}
	}
	return result, nil
}

func compilePolicy(env *cel.Env, expression string) (*compiledPolicy, error) {
	checked, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if !checked.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("expression must return a boolean")
	}
	program, err := env.Program(checked, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(maxPolicyCost))
	if err != nil {
		return nil, err
	}
	uses := make(map[string]bool)
	celast.PreOrderVisit(checked.NativeRep().Expr(), celast.NewExprVisitor(func(expr celast.Expr) {
		if expr.Kind() == celast.IdentKind {
			uses[expr.AsIdent()] = true
		}
	}))
	return &compiledPolicy{program: program, uses: uses}, nil
}

func (p *policySet) forRoute(route *routers.Route) *compiledRoute {
	return p.routes[routeKey{route.Method, route.Path}]
}

func (p *policySet) needs(variable string) bool {
	for _, route := range p.order {
		for _, binding := range route.bindings {
			if binding.rule != nil && binding.rule.uses(variable) {
				return true
			}
		}
	}
	return false
}

func (n *compiledRule) uses(variable string) bool {
	switch n.kind {
	case "cel":
		return n.expr.uses[variable]
	case "ref":
		return n.ref.uses(variable)
	default:
		for _, child := range n.children {
			if child.uses(variable) {
				return true
			}
		}
	}
	return false
}

func (n *compiledRule) validateExpansion(count *int, depth int) error {
	*count += 1
	if *count > maxPolicyEvalNodes || depth > maxPolicyDepth {
		return fmt.Errorf("policy evaluation exceeds depth or node limit")
	}
	if n.ref != nil {
		return n.ref.validateExpansion(count, depth+1)
	}
	for _, child := range n.children {
		if err := child.validateExpansion(count, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (n *compiledRule) evaluate(inputs *requestInputs, params map[string]any) (bool, *policyFailure) {
	switch n.kind {
	case "cel":
		value, _, err := n.expr.program.Eval(&policyActivation{inputs: inputs, params: params})
		if inputs.failure != nil {
			return false, inputs.failure
		}
		if err != nil {
			return false, &policyFailure{status: http.StatusForbidden, code: outcomePolicyError, err: err}
		}
		allowed, ok := value.Value().(bool)
		if !ok {
			return false, &policyFailure{
				status: http.StatusForbidden, code: outcomePolicyError,
				err: fmt.Errorf("policy did not return a boolean"),
			}
		}
		return allowed, nil
	case "ref":
		if len(n.params) == 0 {
			return n.ref.evaluate(inputs, params)
		}
		merged := make(map[string]any, len(params)+len(n.params))
		for name, value := range params {
			merged[name] = value
		}
		for name, value := range n.params {
			merged[name] = value
		}
		return n.ref.evaluate(inputs, merged)
	case "all":
		for _, child := range n.children {
			allowed, failure := child.evaluate(inputs, params)
			if failure != nil || !allowed {
				return false, failure
			}
		}
		return true, nil
	case "any":
		for _, child := range n.children {
			allowed, failure := child.evaluate(inputs, params)
			if failure != nil {
				return false, failure
			}
			if allowed {
				return true, nil
			}
		}
		return false, nil
	case "not":
		allowed, failure := n.children[0].evaluate(inputs, params)
		return !allowed, failure
	default:
		return false, &policyFailure{
			status: http.StatusForbidden, code: outcomePolicyError, err: fmt.Errorf("invalid compiled policy"),
		}
	}
}

func readPolicyBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, int, error) {
	if r.Body == nil {
		return []byte{}, 0, nil
	}
	bounded := http.MaxBytesReader(w, r.Body, limit)
	defer bounded.Close()
	data, err := io.ReadAll(bounded)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, http.StatusRequestEntityTooLarge, err
		}
		return nil, http.StatusBadRequest, fmt.Errorf("read request body: %w", err)
	}
	r.ContentLength = int64(len(data))
	if len(data) == 0 {
		r.Body = http.NoBody
	} else {
		r.Body = io.NopCloser(bytes.NewReader(data))
	}
	return data, 0, nil
}

func parsePolicyJSON(data []byte, contentType string) (any, int, error) {
	if len(data) == 0 {
		return nil, 0, nil
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return nil, http.StatusUnsupportedMediaType, fmt.Errorf("body policy requires JSON Content-Type")
	}
	body, err := decodePolicyJSON(data)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err)
	}
	return body, 0, nil
}

func decodePolicyJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("JSON body must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	values := 0
	body, err := decodeJSONValue(decoder, 0, &values)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return body, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int, count *int) (any, error) {
	*count += 1
	if depth > maxJSONDepth || *count > maxJSONValues {
		return nil, fmt.Errorf("JSON structure exceeds policy limits")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				next, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := next.(string)
				if !ok {
					return nil, fmt.Errorf("invalid JSON object key")
				}
				if _, exists := object[name]; exists {
					return nil, fmt.Errorf("duplicate JSON object key %q", name)
				}
				object[name], err = decodeJSONValue(decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim('}') {
				return nil, fmt.Errorf("invalid JSON object ending")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				element, err := decodeJSONValue(decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				array = append(array, element)
			}
			end, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim(']') {
				return nil, fmt.Errorf("invalid JSON array ending")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	case json.Number:
		number, err := strconv.ParseFloat(string(value), 64)
		if err != nil || math.IsInf(number, 0) || math.Abs(number) >= 1<<53 {
			return nil, fmt.Errorf("JSON number is outside the safe policy range")
		}
		return number, nil
	default:
		return value, nil
	}
}
