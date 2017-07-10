package grok

import (
	"fmt"
	"strings"
)

type patternMap map[string]*grokPattern

func (knownPatterns patternMap) addList(newPatterns map[string]string, namedOnly bool) error {
	dependencies := graph{}
	for key := range knownPatterns {
		dependencies[key] = []string{}
	}

	for key, pattern := range newPatterns {
		referencedKeys := []string{}

		for _, keys := range namedReference.FindAllStringSubmatch(pattern, -1) {
			names := strings.Split(keys[1], ":")
			refKey := names[0]

			if _, keyExists := knownPatterns[refKey]; !keyExists {
				if _, keyExists := newPatterns[refKey]; !keyExists {
					return fmt.Errorf("no pattern found for %%{%s}", refKey)
				}
			}

			referencedKeys = append(referencedKeys, refKey)
		}
		dependencies[key] = referencedKeys
	}

	order, _ := sortGraph(dependencies)
	for _, key := range reverseList(order) {
		knownPatterns.add(key, newPatterns[key], namedOnly)
	}

	return nil
}

func (knownPatterns patternMap) add(name, pattern string, namedOnly bool) error {
	p, err := newGrokPattern(pattern, knownPatterns, namedOnly)
	if err != nil {
		return err
	}

	knownPatterns[name] = p
	return nil
}
