package grok

import (
	"fmt"
	"os"
	"strings"
	"github.com/rtkjweeks/go-pcre"
)

type grokPattern struct {
	origin     string
	expression string
	typeHints  typeHintByKey
	aliasMap   map[string]string
}

var (
	namedReference = pcre.MustCompile(`%{(\w+(?::\w+(?::\w+)?)?)}`, 0)
	replacementReference = pcre.MustCompile(`\(\?\<(\w+)\>`, 0)
)

func newPattern(pattern string, knownPatterns patternMap, namedOnly bool) (*grokPattern, error) {
	aliases := newAliasMap()
	typeHints := typeHintByKey{}

	fmt.Printf("newPattern %s\n", pattern)

	matches, err := FindAllSubstring(namedReference, pattern, 0)
	if err == nil {
		for i := 0; i < len(matches); i++ {
			names := strings.Split(matches[i].NameAndAlias, ":")
			refKey, refAlias := names[0], names[0]
			if len(names) > 1 {
				refAlias = names[1]
			}

			key := matches[i].FullTag

			fmt.Printf("pattern is now %s\n", pattern)
			fmt.Printf("%s %s %s\n", refKey, refAlias, key)

			// Add type cast information only if type set, and not string
			if len(names) == 3 {
				if names[2] != "string" {
					typeHints[refAlias] = names[2]
				}
			}

			refPattern, patternExists := knownPatterns[refKey]
			if !patternExists {
				return nil, fmt.Errorf("no pattern found for %%{%s}", refKey)
			} else {
				fmt.Printf("Using patthern '%s' -> %s\n", refKey, refPattern)
			}

			var refExpression string
			if !namedOnly || (namedOnly && len(names) > 1) {
				refExpression = fmt.Sprintf("(?<%s>%s)", refAlias, refPattern.origin)
			} else {
				refExpression = fmt.Sprintf("(%s)", refPattern.origin)
			}

			// Add new type Informations
			for key, typeName := range refPattern.typeHints {
				if _, hasTypeHint := typeHints[key]; !hasTypeHint {
					typeHints[key] = strings.ToLower(typeName)
				}
			}

			pattern = strings.Replace(pattern, key, refExpression, -1)
		}
	} else {
		return nil, err
	}

	// We've now converted from grok syntax, to a (mostly) valid regex with original names.
	// I say "mostly", because it could have duplicated named groups, or groups with names with underscores (which regex doesn't
	// like).
	// However, *because* it has the original names, and because grok compiling is recursive, we save off this value here.
	// It contains context we want to keep.
	//
	// Note that, above, when recursively replacing grok patterns with their matching patterns, we insert the "origin" string
	// in order to insert the originally named capture groups.
	// 
	// The next step will then modify them altogether and ensures we will always have a direct mapping from the opaque
	// "name</d+>" names, and the names originally provided by the developer, no matter how many recursive insertions are
	// performed before hand.
	var sb strings.Builder
	if _, err := sb.WriteString(pattern); err != nil {
		fmt.Printf("Unable to copy pattern string %s\n", err.Error())
		os.Exit(1)
	}
	origin := sb.String()


	// Iterate the pattern is replace all named capture groups with garaunteed unique names.  We do this because
	// there could be duplicate group names, due to how the substitutions are done, and there could be names that
	// aren't valid to the regex compiler; so we replace them with "name\d+" patterns, and keep a mapping of these
	// back to their original names.
	newMatches, newErr := FindAllSubstring(replacementReference, pattern, 0)
	if newErr == nil {
		for i := 0; i < len(newMatches); i++ {
			name := newMatches[i].NameAndAlias
			uniqueName := aliases.GetUniqueName(name)

			pattern = strings.Replace(pattern, fmt.Sprintf("(?<%s>", name), fmt.Sprintf("(?<%s>", uniqueName), 1)
		}
	}

	return &grokPattern{
		origin:     origin,
		expression: pattern,
		typeHints:  typeHints,
		aliasMap:   aliases.GetMapping(),
	}, nil
}
