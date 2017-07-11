package grok

import (
	"fmt"
	"regexp"
	"strconv"
)

// CompiledGrok represents a compiled Grok expression.
// Use Grok.Compile to generate a CompiledGrok object.
type CompiledGrok struct {
	regexp      *regexp.Regexp
	typeInfo    semanticTypes
	removeEmpty bool
}

type semanticTypes map[string]string

// GetFields returns a list of all named fields in this grok expression
func (compiled CompiledGrok) GetFields() []string {
	return compiled.regexp.SubexpNames()
}

// Match returns true if the given data matches the pattern.
func (compiled CompiledGrok) Match(data []byte) bool {
	return compiled.regexp.Match(data)
}

// MatchString returns true if the given string matches the pattern.
func (compiled CompiledGrok) MatchString(text string) bool {
	return compiled.regexp.MatchString(text)
}

// Parse parses the given data into a key value map.
func (compiled CompiledGrok) Parse(data []byte) map[string][]byte {
	captures := make(map[string][]byte)

	if matches := compiled.regexp.FindSubmatch(data); len(matches) > 0 {
		for idx, key := range compiled.GetFields() {
			match := matches[idx]
			if compiled.omitField(key, match) {
				continue
			}
			captures[key] = match
		}
	}

	return captures
}

// ParseString parses the given string into a key value map.
func (compiled CompiledGrok) ParseString(text string) map[string]string {
	captures := make(map[string]string)

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		for idx, key := range compiled.GetFields() {
			match := matches[idx]
			if compiled.omitStringField(key, match) {
				continue
			}
			captures[key] = match
		}
	}

	return captures
}

// ParseTyped returns a inteface{} map with typed captured fields based on provided pattern over the text
func (compiled CompiledGrok) ParseTyped(data []byte) (map[string]interface{}, error) {
	captures := make(map[string]interface{})

	if matches := compiled.regexp.FindSubmatch(data); len(matches) > 0 {
		for idx, key := range compiled.GetFields() {
			match := matches[idx]
			if compiled.omitField(key, match) {
				continue
			}

			if val, err := compiled.typeCast(string(match), key); err == nil {
				captures[key] = val
			} else {
				return nil, err
			}
		}
	}

	return captures, nil
}

// ParseStringTyped returns a inteface{} map with typed captured fields based on provided pattern over the text
func (compiled CompiledGrok) ParseStringTyped(text string) (map[string]interface{}, error) {
	captures := make(map[string]interface{})

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		for idx, key := range compiled.GetFields() {
			match := matches[idx]
			if compiled.omitStringField(key, match) {
				continue
			}

			if val, err := compiled.typeCast(match, key); err == nil {
				captures[key] = val
			} else {
				return nil, err
			}
		}
	}

	return captures, nil
}

// ParseToMultiMap parses the specified text and returns a map with the
// results. Values are stored in an string slice, so values from captures with
// the same name don't get overridden.
func (compiled CompiledGrok) ParseToMultiMap(data []byte) map[string][][]byte {
	captures := make(map[string][][]byte)

	if matches := compiled.regexp.FindSubmatch(data); len(matches) > 0 {
		for idx, key := range compiled.GetFields() {
			match := matches[idx]
			if compiled.omitField(key, match) {
				continue
			}

			if values, exists := captures[key]; exists {
				captures[key] = append(values, match)
			} else {
				captures[key] = [][]byte{match}
			}
		}
	}

	return captures
}

// ParseStringToMultiMap parses the specified text and returns a map with the
// results. Values are stored in an string slice, so values from captures with
// the same name don't get overridden.
func (compiled CompiledGrok) ParseStringToMultiMap(text string) map[string][]string {
	captures := make(map[string][]string)

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		for idx, key := range compiled.GetFields() {
			match := matches[idx]
			if compiled.omitStringField(key, match) {
				continue
			}

			if values, exists := captures[key]; exists {
				captures[key] = append(values, match)
			} else {
				captures[key] = []string{match}
			}
		}
	}

	return captures
}

func (compiled CompiledGrok) omitField(key string, match []byte) bool {
	return len(key) == 0 || compiled.removeEmpty && len(match) == 0
}

func (compiled CompiledGrok) omitStringField(key, match string) bool {
	return len(key) == 0 || compiled.removeEmpty && len(match) == 0
}

func (compiled CompiledGrok) typeCast(match, key string) (interface{}, error) {
	typeName, hasTypeInfo := compiled.typeInfo[key]
	if !hasTypeInfo {
		return match, nil
	}

	switch typeName {
	case "int":
		return strconv.Atoi(match)

	case "float":
		return strconv.ParseFloat(match, 64)

	case "string":
		return match, nil

	default:
		return nil, fmt.Errorf("ERROR the value %s cannot be converted to %s. Must be int, float, string or empty", match, typeName)
	}
}
