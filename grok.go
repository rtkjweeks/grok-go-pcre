package grok

import (
	"fmt"
	"github.com/rtkjweeks/go-pcre"
)

// Config is used to pass a set of configuration values to the grok.New function.
type Config struct {
	NamedCapturesOnly   bool
	SkipDefaultPatterns bool
	RemoveEmptyValues   bool
	Patterns            map[string]string
}

// Grok holds a cache of known pattern substitions and acts as a builder for
// compiled grok patterns. All pattern substitutions must be passed at creation
// time and cannot be changed during runtime.
type Grok struct {
	patterns    patternMap
	removeEmpty bool
	namedOnly   bool
}

// New returns a Grok object that caches a given set of patterns and creates
// compiled grok patterns based on the passed configuration settings.
// You can use multiple grok objects that act independently.
func New(config Config) (*Grok, error) {
	patterns := patternMap{}

	if !config.SkipDefaultPatterns {
		// Add default patterns first so they can be referenced later
		if err := patterns.addList(DefaultPatterns, config.NamedCapturesOnly); err != nil {
			return nil, err
		}
	}

	// Add passed patterns
	if err := patterns.addList(config.Patterns, config.NamedCapturesOnly); err != nil {
		return nil, err
	}

	fmt.Println("Constructing grok")

	return &Grok{
		patterns:    patterns,
		namedOnly:   config.NamedCapturesOnly,
		removeEmpty: config.RemoveEmptyValues,
	}, nil
}

// Compile precompiles a given grok expression. This function should be used
// when a grok expression is used more than once.
func (grok Grok) Compile(pattern string) (*CompiledGrok, error) {
	grokPattern, err := newPattern(pattern, grok.patterns, grok.namedOnly)
	if err != nil {
		return nil, err
	}

	// JJW: TODO: No flags for now; do we need any?
	compiled, err := pcre.Compile(grokPattern.expression, 0)
	if err != nil {
		return nil, err
	}

	numGroups := compiled.Groups()
	groupIdToName := make([]string, numGroups+1)

	// After compiling, we need to iterate all the capture groups, and
	// map them back to names (After we perform a match, we iterate/lookup
	// results by capture group ID, and then use this to map them back to names)
	for k, v := range grokPattern.aliasMap {
		groupId, err := compiled.GroupNameToIndex(k);
		if err == nil {
			fmt.Printf("  group %s (%s) -> %d\n", k, v, groupId)
			groupIdToName[groupId] = v
		} else {
			fmt.Printf("  group %s (%s) not found!", k, v)
		}
	}


	return &CompiledGrok{
		regexp:        compiled,
		typeHints:     grokPattern.typeHints,
		removeEmpty:   grok.removeEmpty,
		groupIdToName: groupIdToName,
	}, nil
}

// Match returns true if the given data matches the pattern.
// The given pattern is compiled on every call to this function.
// If you want to call this function more than once consider using Compile.
func (grok Grok) Match(pattern string, data []byte) (bool, error) {
	complied, err := grok.Compile(pattern)
	if err != nil {
		return false, err
	}

	return complied.Match(data), nil
}

// MatchString returns true if the given text matches the pattern.
// The given pattern is compiled on every call to this function.
// If you want to call this function more than once consider using Compile.
func (grok Grok) MatchString(pattern, text string) (bool, error) {
	complied, err := grok.Compile(pattern)
	if err != nil {
		return false, err
	}

	return complied.MatchString(text), nil
}
