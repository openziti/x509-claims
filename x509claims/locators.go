package x509claims

import (
	"crypto/x509"
	"net/url"
)

type Locator[M any] interface {
	Locate(cert *x509.Certificate, matcher Matcher[M]) []string
}

var _ Locator[string] = &LocatorCommonName{}

type LocatorCommonName struct{}

func (_ *LocatorCommonName) Locate(cert *x509.Certificate, matcher Matcher[string]) []string {
	if value, ok := matcher.Match(cert.Subject.CommonName); ok {
		return []string{value}
	}

	return []string{}
}

var _ Locator[*url.URL] = &LocatorSanUri{}

type LocatorSanUri struct{}

func (_ *LocatorSanUri) Locate(cert *x509.Certificate, matcher Matcher[*url.URL]) []string {
	var result []string
	for _, uri := range cert.URIs {
		if value, ok := matcher.Match(uri); ok {
			result = append(result, value.String())
		}
	}
	return result
}

var _ Locator[string] = &LocatorSanEmail{}

type LocatorSanEmail struct{}

func (l *LocatorSanEmail) Locate(cert *x509.Certificate, matcher Matcher[string]) []string {
	var result []string
	for _, email := range cert.EmailAddresses {
		if value, ok := matcher.Match(email); ok {
			result = append(result, value)
		}
	}

	return result
}
