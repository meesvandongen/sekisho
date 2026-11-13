package main

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// explainPolicies prints the effective policy of every OpenAPI operation:
// the backend and the binding it came from, the combined required scopes,
// and the checks in evaluation order.
func explainPolicies(ctx context.Context, cfg Config, output io.Writer) error {
	if err := cfg.normalize(); err != nil {
		return err
	}
	_, policies, err := newPolicyRouter(ctx, cfg)
	if err != nil {
		return err
	}
	return writePolicyExplanation(policies, output)
}

func writePolicyExplanation(policies *policySet, output io.Writer) error {
	var text strings.Builder
	for index, route := range policies.order {
		if index > 0 {
			text.WriteString("\n")
		}
		text.WriteString(route.key.method + " " + route.key.path)
		if route.operationID != "" {
			text.WriteString(" (" + route.operationID + ")")
		}
		text.WriteString("\n")
		fmt.Fprintf(&text, "  backend: %s from %s\n", route.backendName, route.backendBinding.label())
		var scopes []string
		seen := make(map[string]bool)
		for _, binding := range route.bindings {
			for _, scope := range binding.requiredScopes {
				if !seen[scope] {
					seen[scope] = true
					scopes = append(scopes, fmt.Sprintf("%s (%s)", scope, binding.label()))
				}
			}
		}
		if len(scopes) > 0 {
			fmt.Fprintf(&text, "  scopes:  %s\n", strings.Join(scopes, ", "))
		}
		var checks []string
		for _, binding := range route.bindings {
			if binding.rule != nil {
				checks = append(checks, binding.label())
			}
		}
		fmt.Fprintf(&text, "  checks:  %s\n", strings.Join(checks, " → "))
	}
	_, err := io.WriteString(output, text.String())
	return err
}
