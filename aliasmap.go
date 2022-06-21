package grok

import (
	"fmt"
)

// This simple helper class provides a way to create unique mappings to potentially non-unique
// names.
// The specific use case this is intended for is grok's with repeating sub-expression names.
//
// Take the following pattern, for example:
//
// SYSLOG_DATE_AND_TIME -> (%{DATE_AND_TIME_1}|%{DATE_AND_TIME_5}|%{DATE_AND_TIME_3})(%{ADDITIONAL_SECONDS_PRECISION:ignore})?(%{TIMEZONE:timezone})?
//
// This is commonly used as a piece of a log line, and matches various different date formats.
// Note, however, that those sub-patterns have repitition in the named values:
//
// DATE_AND_TIME_1 -> %{DATESTAMP_1:datestamp}T%{TIMESTAMP:timestamp}
// DATE_AND_TIME_5 -> %{DATESTAMP_3_NO_YEAR} %{TIMESTAMP:timestamp} %{YEAR:year}
//
// Both of the above contain a named capture group "timestamp"
//
// Attempting to compile a regex with this duplicated name will fail.
//
// The solution, then, is to provide a unique name for each, but maintain a mapping so that we can
// map back to the original/provided name.
//
// As such, when we process a grok and prepare it to be compiled by a pcre compiler, we
// create ambiguous, but unique, names for each capture group (eg. name0, name1, name2) and
// this mapping class is them used to map them back to their original values.

type aliasMap struct {
	nextID int
	aliasMapping map[string]string
}

func newAliasMap() aliasMap {
	return aliasMap { 0, make(map[string]string) }
}

func (am *aliasMap) GetUniqueName(name string) string {
	newName := fmt.Sprintf("name%d", am.nextID)
	am.nextID += 1

	am.aliasMapping[newName] = name

	return newName
}

func (am *aliasMap) GetMapping() map[string]string {
	return am.aliasMapping
}
