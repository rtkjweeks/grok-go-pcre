package grok

import (
	"regexp"
)

// A Config structure is used to configure a Grok parser.
type Config struct {
	NamedCapturesOnly   bool
	SkipDefaultPatterns bool
	RemoveEmptyValues   bool
	Patterns            map[string]string
}

// Grok object us used to load patterns and deconstruct strings using those
// patterns.
type Grok struct {
	patterns    patternMap
	removeEmpty bool
	namedOnly   bool
}

// NewGrok returns a Grok object that is configured to behave according
// to the supplied Config structure.
func NewGrok(config Config) (*Grok, error) {
	patterns := patternMap{}

	if !config.SkipDefaultPatterns {
		// Add default patterns first so they can be referenced later
		if err := patterns.addList(defaultPatterns, config.NamedCapturesOnly); err != nil {
			return nil, err
		}
	}

	// Add passed patterns
	if err := patterns.addList(config.Patterns, config.NamedCapturesOnly); err != nil {
		return nil, err
	}

	return &Grok{
		patterns:    patterns,
		namedOnly:   config.NamedCapturesOnly,
		removeEmpty: config.RemoveEmptyValues,
	}, nil
}

// Compile precompiles a given expression. This function should be used when a
// grok expression is used more than once.
func (grok Grok) Compile(pattern string) (*CompiledGrok, error) {
	grokPattern, err := newGrokPattern(pattern, grok.patterns, grok.namedOnly)
	if err != nil {
		return nil, err
	}

	compiled, err := regexp.Compile(grokPattern.expression)
	if err != nil {
		return nil, err
	}

	return &CompiledGrok{
		regexp:      compiled,
		typeInfo:    grokPattern.typeInfo,
		removeEmpty: grok.removeEmpty,
	}, nil
}

// Match returns true if the specified text matches the pattern.
// The given pattern is compiled on every call to this function.
// If you want to reuse your pattern please use Compile.
func (grok Grok) Match(pattern, text string) (bool, error) {
	complied, err := grok.Compile(pattern)
	if err != nil {
		return false, err
	}

	return complied.Match(text), nil
}

// Parse the specified text and return a map with the results.
// The given pattern is compiled on every call to this function.
// If you want to reuse your pattern please use Compile.
func (grok Grok) Parse(pattern, text string) (map[string]string, error) {
	complied, err := grok.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return complied.Parse(text), nil
}

// ParseTyped returns a inteface{} map with typed captured fields based on
// provided pattern over the text.
// The given pattern is compiled on every call to this function.
// If you want to reuse your pattern please use Compile.
func (grok Grok) ParseTyped(pattern, text string) (map[string]interface{}, error) {
	complied, err := grok.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return complied.ParseTyped(text)
}

// ParseToMultiMap parses the specified text and returns a map with the
// results. Values are stored in an string slice, so values from captures with
// the same name don't get overridden.
// The given pattern is compiled on every call to this function.
// If you want to reuse your pattern please use Compile.
func (grok Grok) ParseToMultiMap(pattern, text string) (map[string][]string, error) {
	complied, err := grok.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return complied.ParseToMultiMap(text), nil
}
