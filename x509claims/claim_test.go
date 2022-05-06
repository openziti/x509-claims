package x509claims

import (
	"crypto/x509"
	"github.com/stretchr/testify/require"
	"net/url"
	"strings"
	"testing"
)

func TestConfig_Claims(t *testing.T) {

	t.Run("can parse a single claim from a single URI SANs", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[*url.URL]{
					Locator: &LocatorSanUri{},
					Matcher: &MatcherScheme{Scheme: "spiffe"},
					Parser:  &ParserNoOp{},
				},
			},
		}

		urlStr := "spiffe://mytrustdomain/myidentity"
		spiffeUrl, err := url.Parse(urlStr)
		req.NoError(err)

		nonSpiffeUrl, err := url.Parse("nomatch://not/here/man")
		req.NoError(err)

		cert := &x509.Certificate{
			URIs: []*url.URL{
				spiffeUrl,
				nonSpiffeUrl,
			},
		}

		claims := provider.Claims(cert)
		req.Equal([]string{urlStr}, claims)
	})

	t.Run("can parse multiple claims from multiple URI SANs", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[*url.URL]{
					Locator: &LocatorSanUri{},
					Matcher: &MatcherScheme{Scheme: "spiffe"},
					Parser:  &ParserNoOp{},
				},
			},
		}

		urlStr1 := "spiffe://mytrustdomain/myidentity1"
		urlStr2 := "spiffe://mytrustdomain/myidentity2"

		spiffeUrl1, err := url.Parse(urlStr1)
		req.NoError(err)

		spiffeUrl2, err := url.Parse(urlStr2)
		req.NoError(err)

		nonSpiffeUrl, err := url.Parse("nomatch://not/here/man")
		req.NoError(err)

		cert := &x509.Certificate{
			URIs: []*url.URL{
				spiffeUrl1,
				nonSpiffeUrl,
				spiffeUrl2,
			},
		}

		claims := provider.Claims(cert)
		req.Equal([]string{urlStr1, urlStr2}, claims)
	})

	t.Run("can parse a single claim from a single email san", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorSanEmail{},
					Matcher: &MatcherSuffix{Suffix: "@ziti.dev"},
					Parser:  &ParserSplit{Separator: "."},
				},
			},
		}

		claim1 := "claim1"
		cert := &x509.Certificate{
			EmailAddresses: []string{
				"hello@nomatch.com",
				claim1 + "@ziti.dev",
			},
		}

		claims := provider.Claims(cert)
		req.Equal([]string{claim1}, claims)
	})

	t.Run("can parse multiple claims from a single email san", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorSanEmail{},
					Matcher: &MatcherSuffix{Suffix: "@ziti.dev"},
					Parser:  &ParserSplit{Separator: "."},
				},
			},
		}

		claim1 := "claim1"
		claim2 := "claim2"

		cert := &x509.Certificate{
			EmailAddresses: []string{
				"hello@nomatch.com",
				strings.Join([]string{claim1, claim2}, ".") + "@ziti.dev",
			},
		}

		claims := provider.Claims(cert)
		req.Equal([]string{claim1, claim2}, claims)
	})

	t.Run("can parse multiple claims from multiple email san with various parsing logic", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorSanEmail{},
					Matcher: &MatcherSuffix{Suffix: "@ziti.dev"},
					Parser:  &ParserSplit{Separator: "."},
				},
				&DefinitionLMP[string]{
					Locator: &LocatorSanEmail{},
					Matcher: &MatcherSuffix{Suffix: "@other.dev"},
					Parser:  &ParserNoOp{},
				},
			},
		}

		claim1 := "claim1"
		claim2 := "claim2"
		claim3 := "claim3.should.not.be.parsed"
		cert := &x509.Certificate{
			EmailAddresses: []string{
				"hello@nomatch.com",
				strings.Join([]string{claim1, claim2}, ".") + "@ziti.dev",
				claim3 + "@other.dev",
			},
		}

		claims := provider.Claims(cert)
		req.Equal([]string{claim1, claim2, claim3}, claims)
	})

	t.Run("can parse a single claim from the common name", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorCommonName{},
					Matcher: &MatcherAll[string]{},
					Parser:  &ParserNoOp{},
				},
			},
		}

		commonName := "some.really.long.claim"

		cert := &x509.Certificate{}
		cert.Subject.CommonName = commonName

		claims := provider.Claims(cert)
		req.Equal([]string{commonName}, claims)
	})

	t.Run("can parse multiple claims from the common name", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorCommonName{},
					Matcher: &MatcherAll[string]{},
					Parser:  &ParserSplit{Separator: "."},
				},
			},
		}

		claims := []string{"claim1", "claim2", "claim3"}

		commonName := strings.Join(claims, ".")

		cert := &x509.Certificate{}
		cert.Subject.CommonName = commonName

		resultClaims := provider.Claims(cert)
		req.Equal(claims, resultClaims)
	})

	t.Run("can parse multiple claims from the common name with a prefix", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorCommonName{},
					Matcher: &MatcherPrefix{Prefix: "SENTINEL:"},
					Parser:  &ParserSplit{Separator: "."},
				},
			},
		}

		claims := []string{"claim1", "claim2", "claim3"}

		commonName := "SENTINEL:" + strings.Join(claims, ".")

		cert := &x509.Certificate{}
		cert.Subject.CommonName = commonName

		resultClaims := provider.Claims(cert)
		req.Equal(claims, resultClaims)
	})

	t.Run("can parse 0 claims from the common name with an invalid prefix", func(t *testing.T) {
		req := require.New(t)

		provider := ProviderBasic{
			Definitions: []Definition{
				&DefinitionLMP[string]{
					Locator: &LocatorCommonName{},
					Matcher: &MatcherPrefix{Prefix: "SENTINEL:"},
					Parser:  &ParserSplit{Separator: "."},
				},
			},
		}

		claims := []string{"claim1", "claim2", "claim3"}

		commonName := "IGOBOOM:" + strings.Join(claims, ".")

		cert := &x509.Certificate{}
		cert.Subject.CommonName = commonName

		resultClaims := provider.Claims(cert)
		req.Nil(resultClaims)
	})
}
