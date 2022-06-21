package grok

import (
	"github.com/rtkjweeks/go-pcre"
)

func maxInt(x, y int) int {
	if x > y {
		return x
	} else {
		return y
	}
}

type GrokReplacementMatch struct {
	NameAndAlias string
	FullTag string
}

// This is a slight tweak of FindAll in the go-pcre package:
// https://github.com/rubrikinc/go-pcre/blob/master/pcre.go#L633
//
// But rather than return the whole string in the Match::Finding, it returns the capture.
// The indices still return the bounds of the whole matching string.
//
// This is more aligned with the FindAllStringSubmatch() from go's regex (RE2 based) 
// library and, at least for the sake of this grok library, can be slotted it as a 
// functionally equivalent version, but based on a PCRE2 regex.
//
// More succinctly, given a grok pattern as a subject:
// %{PRI} %{HOSTNAME:remoteip}
//
// And attempting to find all grok tags (eg. FindAll w/ re == "%{(\w+(?::\w+(?::\w+)?)?)}" )
//
// Match.NameAndAlias will contain "PRI" and "HOSTNAME:remoteip" (i.e., the capture), while
// Match.FullTag will contain the full match string ("%{PRI}" and "%{HOSTNAME:remoteip}")
func FindAllSubstring(re pcre.Regexp, subject string, flags int) ([]GrokReplacementMatch, error) {
	matches := make([]GrokReplacementMatch, 0)
	m := re.MatcherString(subject, flags)
	offset := 0
	for m.Matches() {
		strs := m.ExtractString()
		loc := m.Index()
		leftIdx := loc[0] + offset
		rightIdx := loc[1] + offset

		matches = append(
			matches,
			GrokReplacementMatch{
				strs[1],  // strs[0] is the whole thing, strs[1] is the capture
				subject[leftIdx:rightIdx], // the whole tag
			},
		)
		offset += maxInt(1, loc[1])
		if offset < len(subject) {
			m.MatchString(subject[offset:], flags)
		} else {
			break
		}
	}
	return matches, nil // TODO: can this error out?
}
