package grok

import (
	"fmt"
	"strings"
)

type patternMap map[string]*grokPattern

// resolve references inside a pattern so that all substitutions are added
// in the correct order.
func (knownPatterns *patternMap) resolve(key, pattern string, newPatterns map[string]string, namedOnly bool) error {
	fmt.Printf("Resolve %s -> %s\n", key, pattern)
	// find all grok named references: eg: %{MONTH_NUMBER:month}
	matches, err := FindAllSubstring(namedReference, pattern, 0)
	if err == nil {
		for i := 0; i < len(matches); i++ {
			names := strings.Split(matches[i].NameAndAlias, ":")
			refKey := names[0]

			// if we haven't already compiled it, take it from the pattern list and compile it
			// first because this current pattern refers to it, so we must resolve it first...
			if _, refKeyCompiled := (*knownPatterns)[refKey]; !refKeyCompiled {
				refPattern, refKeyFound := newPatterns[refKey]
				if !refKeyFound {
					return fmt.Errorf("no pattern found for %%{%s}", refKey)
				}
				knownPatterns.resolve(refKey, refPattern, newPatterns, namedOnly)
			}
		}
	} else {
		return err
	}
	return knownPatterns.add(key, pattern, namedOnly)
}

// add a list of patterns to the map
func (knownPatterns *patternMap) addList(newPatterns map[string]string, namedOnly bool) error {
	for key, pattern := range newPatterns {
		if _, alreadyCompiled := (*knownPatterns)[key]; alreadyCompiled {
			continue
		}
		if err := knownPatterns.resolve(key, pattern, newPatterns, namedOnly); err != nil {
			return err
		}
	}

	return nil
}

// add a single pattern to the map
func (knownPatterns *patternMap) add(name, pattern string, namedOnly bool) error {
	fmt.Printf("Adding pattern %s -> %s\n", name, pattern)
	p, err := newPattern(pattern, *knownPatterns, namedOnly)
	if err != nil {
		return err
	}

	(*knownPatterns)[name] = p
	return nil
}
