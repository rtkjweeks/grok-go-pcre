package grok

import (
	"fmt"
	"regexp"
	"strings"
)

type grokPattern struct {
	expression string
	typeInfo   semanticTypes
}

var (
	namedReference = regexp.MustCompile(`%{(\w+(?::\w+(?::\w+)?)?)}`)
)

func newGrokPattern(pattern string, knownPatterns patternMap, namedOnly bool) (*grokPattern, error) {
	typeInfo := semanticTypes{}

	for _, keys := range namedReference.FindAllStringSubmatch(pattern, -1) {

		names := strings.Split(keys[1], ":")
		refKey, semantic := names[0], names[0]
		if len(names) > 1 {
			semantic = names[1]
		}

		// Add type cast information only if type set, and not string
		if len(names) == 3 {
			if names[2] != "string" {
				typeInfo[semantic] = names[2]
			}
		}

		refPattern, patternExists := knownPatterns[refKey]
		if !patternExists {
			return nil, fmt.Errorf("no pattern found for %%{%s}", refKey)
		}

		var refExpression string
		if !namedOnly || (namedOnly && len(names) > 1) {
			refExpression = fmt.Sprintf("(?P<%s>%s)", semantic, refPattern.expression)
		} else {
			refExpression = fmt.Sprintf("(%s)", refPattern.expression)
		}

		// Add new type Informations
		for key, semanticName := range refPattern.typeInfo {
			if _, hasTypeInfo := typeInfo[key]; !hasTypeInfo {
				typeInfo[key] = strings.ToLower(semanticName)
			}
		}

		pattern = strings.Replace(pattern, keys[0], refExpression, -1)
	}

	return &grokPattern{
		expression: pattern,
		typeInfo:   typeInfo,
	}, nil
}
