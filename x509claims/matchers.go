package x509claims

import (
	"net/url"
	"strings"
)

type Matcher[T any] interface {
	Match(value T) (T, bool)
}

var _ Matcher[string] = &MatcherPrefix{}

type MatcherPrefix struct {
	Prefix string
}

func (m *MatcherPrefix) Match(value string) (string, bool) {
	return strings.TrimPrefix(value, m.Prefix), strings.HasPrefix(value, m.Prefix)
}

var _ Matcher[string] = &MatcherSuffix{}

type MatcherSuffix struct {
	Suffix string
}

func (m *MatcherSuffix) Match(value string) (string, bool) {
	return strings.TrimSuffix(value, m.Suffix), strings.HasSuffix(value, m.Suffix)
}

var _ Matcher[*url.URL] = &MatcherScheme{}

type MatcherScheme struct {
	Scheme string
}

func (m *MatcherScheme) Match(uri *url.URL) (*url.URL, bool) {
	return uri, uri.Scheme == m.Scheme
}

var _ Matcher[int] = &MatcherAll[int]{}

type MatcherAll[T any] struct{}

func (m *MatcherAll[T]) Match(value T) (T, bool) {
	return value, true
}
