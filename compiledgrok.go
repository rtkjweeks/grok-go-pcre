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

// Match returns true if the given string matches the pattern.
func (compiled CompiledGrok) Match(text string) bool {
	return compiled.regexp.MatchString(text)
}

// Parse parses the given string into a key value map.
func (compiled CompiledGrok) Parse(text string) map[string]string {
	captures := make(map[string]string)

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			if name == "" {
				continue
			}
			if compiled.removeEmpty && matches[idx] == "" {
				continue
			}
			captures[name] = matches[idx]
		}
	}

	return captures
}

// ParseTyped returns a inteface{} map with typed captured fields based on provided pattern over the text
func (compiled CompiledGrok) ParseTyped(text string) (map[string]interface{}, error) {
	captures := make(map[string]interface{})

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			if name == "" {
				continue
			}
			if compiled.removeEmpty && matches[idx] == "" {
				continue
			}

			typeName, hasTypeInfo := compiled.typeInfo[name]
			if !hasTypeInfo {
				captures[name] = matches[idx]
				continue
			}

			var err error
			switch typeName {
			case "int":
				captures[name], err = strconv.Atoi(matches[idx])
				if err != nil {
					return nil, err
				}

			case "float":
				captures[name], err = strconv.ParseFloat(matches[idx], 64)
				if err != nil {
					return nil, err
				}

			case "string":
				captures[name] = matches[idx]

			default:
				return nil, fmt.Errorf("ERROR the value %s cannot be converted to %s. Must be int, float, string or empty", matches[idx], name)
			}
		}
	}

	return captures, nil
}

// ParseToMultiMap parses the specified text and returns a map with the
// results. Values are stored in an string slice, so values from captures with
// the same name don't get overridden.
func (compiled CompiledGrok) ParseToMultiMap(text string) map[string][]string {
	captures := make(map[string][]string)

	if matches := compiled.regexp.FindStringSubmatch(text); len(matches) > 0 {
		subExpNames := compiled.regexp.SubexpNames()
		for idx, name := range subExpNames {
			if name == "" {
				continue
			}
			if compiled.removeEmpty && matches[idx] == "" {
				continue
			}

			if values, exists := captures[name]; exists {
				captures[name] = append(values, matches[idx])
			} else {
				captures[name] = []string{matches[idx]}
			}
		}
	}

	return captures
}
