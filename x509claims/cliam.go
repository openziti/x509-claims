// Package x509claims provides declaration based configuration for retrieving string claims from a x509 certificate.
// This package does not attempt to verify the signature or chains of trust associated with a certificate as that is
// a solved problem. It is expected, that any claims retrieved with this package are being done so on  certificates
// that have already been verified as "trusted".
//
// Package x509claims provides an interface framework that is meant to be extended with project specific claims
// needs. Out of the box it supports Locator -> Matcher -> Parser (LMP) Definition (DefinitionLMP). Users can either add
// their own Definition with their own conventions or add custom Locator, Matcher, and/or Parser implementations to plug
// into the existing DefinitionLMP. They can even implement their own Provider with its own rules if necessary.
//
// The following example show how to add a DefinitionLMP that will parse out any SPIFFE ID from a x509.Certificate
// SVID. As a note, the current SPIFFE spec allows only 1 SPIFFE ID per SVID. This example would return ALL
// URI SANs wit the scheme `spiffe`. It would be up the implementor to only use the first value per the SPIFFE spec.
//
// Example:
// ```
//		provider := ProviderBasic{
//			Definitions: []Definition{
//				&DefinitionLMP[*url.URL]{
//					Locator: &LocatorUriSan{},
//					Matcher: &MatcherScheme{Scheme: "spiffe"},
//					Parser:  &ParserNoOp{},
//				},
//			},
//		}
// ```
//
// The following example returns SPIFFE IDs as well as email claims from an email SAN:
// Example:
// ```
//		provider := ProviderBasic{
//			Definitions: []Definition{
//				&DefinitionLMP[*url.URL]{
//					Locator: &LocatorUriSan{},
//					Matcher: &MatcherScheme{Scheme: "spiffe"},
//					Parser:  &ParserNoOp{},
//				},
//			},
//             	&DefinitionLMP[string]{
//					Locator: &LocatorSanEmail{},
//					Matcher: &MatcherSuffix{Suffix: "@my.domain.dev"},
//					Parser:  &ParserSplit{Separator: "."},
//			},
//		}
// ```
package x509claims

import (
	"crypto/x509"
)

// Provider is the top level interface. When Claims() is invoked on a
// given x509.Certificate it should return an array of string claims.
type Provider interface {
	Claims(cert *x509.Certificate) []string
}

// ProviderBasic is a default implementation of Provider. It holds all the claims
// definitions that should be used to return string claims via Claims() by invoking
// Definition.Claims().
type ProviderBasic struct {
	Definitions []Definition
}

// Claims returns a string array of claims that have been retrieved
// from a certificate based upon the ProviderBasic's definitions.
func (c *ProviderBasic) Claims(cert *x509.Certificate) []string {
	var result []string

	for _, def := range c.Definitions {
		result = append(result, def.Claims(cert)...)
	}
	return result
}

// Definition implementors should be able to return an array string claims
// based on a given x509.Certificate. `x509-claims` comes with one
// implementation of this interface: DefinitionLMP.
type Definition interface {
	Claims(cert *x509.Certificate) []string
}

// DefinitionLMP implements Definition and allows for assembly of a Locator,
// Matcher, and Parser (LMP). The Locator retrieves data structures of type `M`.
// Those data structures are fed into a Matcher which matches and modifies
// those structures (i.e. to remove non-claims values like sentinel values).
// Finally, the locator values are converted into strings that are passed to a
// Parser to convert a single string to multiple string claims.
type DefinitionLMP[M any] struct {
	Locator Locator[M]
	Matcher Matcher[M]
	Parser  Parser
}

// Claims invokes the definitions Locator and Matcher to produce an array
// of string values that can be parsed into claims.
func (d *DefinitionLMP[M]) Claims(cert *x509.Certificate) []string {
	var result []string
	for _, value := range d.Locator.Locate(cert, d.Matcher) {
		result = append(result, d.Parser.Parse(value)...)
	}

	return result
}
