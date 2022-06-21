package grok

import (
	"fmt"
	"strconv"
	"github.com/rtkjweeks/go-pcre"
)

// CompiledGrok represents a compiled Grok expression.
// Use Grok.Compile to generate a CompiledGrok object.
type CompiledGrok struct {
	regexp        pcre.Regexp
	typeHints     typeHintByKey
	removeEmpty   bool
	groupIdToName []string
}

type typeHintByKey map[string]string

// Match returns true if the given data matches the pattern.
func (compiled CompiledGrok) Match(data []byte) bool {
	matcher := compiled.regexp.NewMatcher()
	return matcher.Match(data, 0)
}

// MatchString returns true if the given text matches the pattern.
func (compiled CompiledGrok) MatchString(text string) bool {
	matcher := compiled.regexp.NewMatcher()
	return matcher.MatchString(text, 0)
}


// MatchAgainst
// returns true if the given text matches the pattern.
//         An object which can be used to extract individual matches by name
func (compiled CompiledGrok) MatchAgainst(text string) (bool, map[string]string) {
	matcher := compiled.regexp.NewMatcher()
	matched :=  matcher.MatchString(text, 0)

	values := make(map[string]string)
	if matched {
		// Now that we've matched, find out which capture groups are present, and map
		// them back to names in order to provide a key/value map back to the
		// caller
		for i := 0; i <= matcher.Groups(); i++ {
			if matcher.Present(i) {
				values[ compiled.groupIdToName[i] ] = matcher.GroupString(i)
			}
		}
	}

	return matched, values
}

// omitField return true if the field is to be omitted
func (compiled CompiledGrok) omitField(key string, match []byte) bool {
	return len(key) == 0 || compiled.removeEmpty && len(match) == 0
}

// omitStringField return true if the field is to be omitted
func (compiled CompiledGrok) omitStringField(key, match string) bool {
	return len(key) == 0 || compiled.removeEmpty && len(match) == 0
}

// typeCast casts a field based on a typehint
func (compiled CompiledGrok) typeCast(match, key string) (interface{}, error) {
	typeName, hasTypeHint := compiled.typeHints[key]
	if !hasTypeHint {
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
