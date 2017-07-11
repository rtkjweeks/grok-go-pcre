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
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			match := matches[idx]
			if compiled.omitField(name, match) {
				continue
			}
			captures[name] = match
		}
	}

	return captures
}

// ParseString parses the given string into a key value map.
func (compiled CompiledGrok) ParseString(text string) map[string]string {
	captures := make(map[string]string)

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			match := matches[idx]
			if compiled.omitStringField(name, match) {
				continue
			}
			captures[name] = match
		}
	}

	return captures
}

// ParseTyped returns a inteface{} map with typed captured fields based on provided pattern over the text
func (compiled CompiledGrok) ParseTyped(data []byte) (map[string]interface{}, error) {
	captures := make(map[string]interface{})

	if matches := compiled.regexp.FindSubmatch(data); len(matches) > 0 {
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			match := matches[idx]
			if compiled.omitField(name, match) {
				continue
			}

			typeName, hasTypeInfo := compiled.typeInfo[name]
			if !hasTypeInfo {
				captures[name] = match
				continue
			}

			if val, err := typeCast(string(match), typeName); err == nil {
				captures[name] = val
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
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			match := matches[idx]
			if compiled.omitStringField(name, match) {
				continue
			}

			typeName, hasTypeInfo := compiled.typeInfo[name]
			if !hasTypeInfo {
				captures[name] = match
				continue
			}

			if val, err := typeCast(match, typeName); err == nil {
				captures[name] = val
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
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			match := matches[idx]
			if compiled.omitField(name, match) {
				continue
			}

			if values, exists := captures[name]; exists {
				captures[name] = append(values, match)
			} else {
				captures[name] = [][]byte{match}
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
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			match := matches[idx]
			if compiled.omitStringField(name, match) {
				continue
			}

			if values, exists := captures[name]; exists {
				captures[name] = append(values, match)
			} else {
				captures[name] = []string{match}
			}
		}
	}

	return captures
}

func (compiled CompiledGrok) omitField(name string, match []byte) bool {
	return len(name) == 0 || compiled.removeEmpty && len(match) == 0
}

func (compiled CompiledGrok) omitStringField(name, match string) bool {
	return len(name) == 0 || compiled.removeEmpty && len(match) == 0
}

func typeCast(match, typeName string) (interface{}, error) {
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
