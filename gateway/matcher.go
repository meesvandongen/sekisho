package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"reflect"
	"strings"
)

const (
	maxMatcherNodes = 4096
	maxMatcherDepth = 16
)

// PolicyMatcher selects OpenAPI operations for a route binding. It is either
// the string "*" or an object whose conditions must all hold.
type PolicyMatcher struct {
	Wildcard    bool            `json:"-"`
	OperationID stringList      `json:"operation_id"`
	Method      stringList      `json:"method"`
	Path        stringList      `json:"path"`
	PathPrefix  stringList      `json:"path_prefix"`
	Tag         stringList      `json:"tag"`
	Extension   map[string]any  `json:"extension"`
	All         []PolicyMatcher `json:"all"`
	Any         []PolicyMatcher `json:"any"`
	Not         *PolicyMatcher  `json:"not"`
}

func (m *PolicyMatcher) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return err
		}
		if value != "*" {
			return fmt.Errorf(`match string must be "*"`)
		}
		*m = PolicyMatcher{Wildcard: true}
		return nil
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf(`match must be "*" or an object`)
	}
	type plain PolicyMatcher
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	*m = PolicyMatcher(decoded)
	return nil
}

// stringList accepts either a single JSON string or an array of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return err
		}
		*l = stringList{value}
		return nil
	}
	var values []string
	if err := json.Unmarshal(trimmed, &values); err != nil {
		return fmt.Errorf("expected a string or an array of strings")
	}
	if values == nil {
		values = []string{}
	}
	*l = values
	return nil
}

type operationInfo struct {
	key        routeKey
	id         string
	tags       []string
	extensions map[string]any
}

type operationIndex struct {
	operations []operationInfo
	byID       map[string]int
	paths      map[string]bool
	tags       map[string]bool
}

type operationSet []uint64

func newOperationSet(size int) operationSet { return make(operationSet, (size+63)/64) }

func (s operationSet) add(index int)           { s[index/64] |= 1 << (index % 64) }
func (s operationSet) contains(index int) bool { return s[index/64]&(1<<(index%64)) != 0 }

func (s operationSet) count() int {
	total := 0
	for _, word := range s {
		total += bits.OnesCount64(word)
	}
	return total
}

func (s operationSet) intersect(other operationSet) {
	for index := range s {
		s[index] &= other[index]
	}
}

func (s operationSet) union(other operationSet) {
	for index := range s {
		s[index] |= other[index]
	}
}

func (s operationSet) subsetOf(other operationSet) bool {
	for index := range s {
		if s[index]&^other[index] != 0 {
			return false
		}
	}
	return true
}

type matcherCompiler struct {
	index *operationIndex
	nodes int
}

func (c *matcherCompiler) selectOperations(matcher PolicyMatcher, depth int) (operationSet, error) {
	c.nodes++
	if c.nodes > maxMatcherNodes || depth > maxMatcherDepth {
		return nil, fmt.Errorf("match exceeds depth or node limit")
	}
	size := len(c.index.operations)
	selected := newOperationSet(size)
	for index := range c.index.operations {
		selected.add(index)
	}
	if matcher.Wildcard {
		return selected, nil
	}
	conditions := 0
	filter := func(keep func(operationInfo) bool) {
		conditions++
		next := newOperationSet(size)
		for index, operation := range c.index.operations {
			if keep(operation) {
				next.add(index)
			}
		}
		selected.intersect(next)
	}
	if matcher.OperationID != nil {
		ids, err := nonEmptyList("operation_id", matcher.OperationID)
		if err != nil {
			return nil, err
		}
		for id := range ids {
			if _, ok := c.index.byID[id]; !ok {
				return nil, fmt.Errorf("unknown operationId %q", id)
			}
		}
		filter(func(operation operationInfo) bool { return ids[operation.id] })
	}
	if matcher.Method != nil {
		methods, err := nonEmptyList("method", matcher.Method)
		if err != nil {
			return nil, err
		}
		normalized := make(map[string]bool, len(methods))
		for method := range methods {
			upper := strings.ToUpper(method)
			switch upper {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT":
			default:
				return nil, fmt.Errorf("unknown HTTP method %q", method)
			}
			normalized[upper] = true
		}
		filter(func(operation operationInfo) bool { return normalized[operation.key.method] })
	}
	if matcher.Path != nil {
		paths, err := nonEmptyList("path", matcher.Path)
		if err != nil {
			return nil, err
		}
		for path := range paths {
			if !c.index.paths[path] {
				return nil, fmt.Errorf("unknown OpenAPI path %q", path)
			}
		}
		filter(func(operation operationInfo) bool { return paths[operation.key.path] })
	}
	if matcher.PathPrefix != nil {
		prefixes, err := nonEmptyList("path_prefix", matcher.PathPrefix)
		if err != nil {
			return nil, err
		}
		for prefix := range prefixes {
			if !strings.HasPrefix(prefix, "/") {
				return nil, fmt.Errorf("path_prefix %q must start with /", prefix)
			}
		}
		filter(func(operation operationInfo) bool {
			for prefix := range prefixes {
				if pathHasPrefix(operation.key.path, prefix) {
					return true
				}
			}
			return false
		})
	}
	if matcher.Tag != nil {
		tags, err := nonEmptyList("tag", matcher.Tag)
		if err != nil {
			return nil, err
		}
		for tag := range tags {
			if !c.index.tags[tag] {
				return nil, fmt.Errorf("unknown OpenAPI tag %q", tag)
			}
		}
		filter(func(operation operationInfo) bool {
			for _, tag := range operation.tags {
				if tags[tag] {
					return true
				}
			}
			return false
		})
	}
	if matcher.Extension != nil {
		if len(matcher.Extension) == 0 {
			return nil, fmt.Errorf("extension requires at least one x- key")
		}
		expected := make(map[string]any, len(matcher.Extension))
		for name, value := range matcher.Extension {
			if !strings.HasPrefix(name, "x-") {
				return nil, fmt.Errorf("extension key %q must start with x-", name)
			}
			normalized, err := normalizeJSONValue(value)
			if err != nil {
				return nil, fmt.Errorf("extension %q: %w", name, err)
			}
			expected[name] = normalized
		}
		filter(func(operation operationInfo) bool {
			for name, value := range expected {
				actual, ok := operation.extensions[name]
				if !ok || !reflect.DeepEqual(actual, value) {
					return false
				}
			}
			return true
		})
	}
	if matcher.All != nil {
		conditions++
		if len(matcher.All) == 0 {
			return nil, fmt.Errorf("all requires at least one matcher")
		}
		for _, child := range matcher.All {
			childSet, err := c.selectOperations(child, depth+1)
			if err != nil {
				return nil, err
			}
			selected.intersect(childSet)
		}
	}
	if matcher.Any != nil {
		conditions++
		if len(matcher.Any) == 0 {
			return nil, fmt.Errorf("any requires at least one matcher")
		}
		combined := newOperationSet(size)
		for _, child := range matcher.Any {
			childSet, err := c.selectOperations(child, depth+1)
			if err != nil {
				return nil, err
			}
			combined.union(childSet)
		}
		selected.intersect(combined)
	}
	if matcher.Not != nil {
		conditions++
		childSet, err := c.selectOperations(*matcher.Not, depth+1)
		if err != nil {
			return nil, err
		}
		inverted := newOperationSet(size)
		for index := range c.index.operations {
			if !childSet.contains(index) {
				inverted.add(index)
			}
		}
		selected.intersect(inverted)
	}
	if conditions == 0 {
		return nil, fmt.Errorf(`match needs at least one condition; use "*" to select every operation`)
	}
	return selected, nil
}

func nonEmptyList(name string, values stringList) (map[string]bool, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s requires at least one value", name)
	}
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" {
			return nil, fmt.Errorf("%s values must not be empty", name)
		}
		result[value] = true
	}
	return result, nil
}

// pathHasPrefix compares whole path segments, so /admin matches /admin and
// /admin/users but not /administrators.
func pathHasPrefix(path, prefix string) bool {
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed == "" {
		return true
	}
	return path == trimmed || strings.HasPrefix(path, trimmed+"/")
}

func normalizeJSONValue(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}
