# x509-claims

`x509-claims` provides declaration based configuration for retrieving string claims from a x509 certificate.
This package does not attempt to verify the signature or chains of trust associated with a certificate as that is
a solved problem. It is expected, that any claims retrieved with this package are being done so on certificates
that have already been verified as "trusted".

`x509-claims` provides an interface framework that is meant to be extended with project specific claims needs. Out of
the box it supports a `Locator` -> `Matcher` -> `Parser` Definition. Users can either add their own Definition with
their own conventions or add custom `Locator`, `Matcher`, and/or `Parser` implementations to plug into the existing
`DefinitionLMP`. They can even implement their own Provider with its own rules if necessary.

The following example show how to add a `DefinitionLMP` that will parse out any SPIFFE ID from a x509.Certificate
SVID. As a note, the current SPIFFE spec allows only 1 SPIFFE ID per SVID. This example would return ALL
URI SANs wit the scheme `spiffe`. It would be up the implementor to only use the first value per the SPIFFE spec.

Example:

```
provider := ProviderBasic{
    Definitions: []Definition{
        &DefinitionLMP[*url.URL]{
            Locator: &LocatorUriSan{},
            Matcher: &MatcherScheme{Scheme: "spiffe"},
            Parser:  &ParserNoOp{},
        },
    },
}
```

The following example returns SPIFFE IDs as well as email claims from an email SAN.

Example:

```
provider := ProviderBasic{
    Definitions: []Definition{
        &DefinitionLMP[*url.URL]{
            Locator: &LocatorUriSan{},
            Matcher: &MatcherScheme{Scheme: "spiffe"},
            Parser:  &ParserNoOp{},
        },
    },
        &DefinitionLMP[string]{
            Locator: &LocatorSanEmail{},
            Matcher: &MatcherSuffix{Suffix: "@my.domain.dev"},
            Parser:  &ParserSplit{Separator: "."},
    },
}
```

## Example Program

This repository is meant to be used as a library, however it provides an example program under `cmd/x509-claims` is an
example parsing program. It can be run on the example file in `data/example.svid.cert`.

This program is intended as a working example for developers new to dealing with x509 Certificates in go. It provides
an example of parsing a single PEM encoded file into DER and then parsing DER into go x509.Certificates.
Additionally, it parses out any SPIFFE IDs from those certificates.

```
x509-claims -h

This program is an example implementation of x509-claims. It parses out SPIFFE IDs from x509 Certificates.
	
Usage:
        x509-claims [-h] <cert-pem-file>
```

Example Run:

```
x509-claims data/example.svid.cert
...parsed 2 certificates

--- cert 1
        spiffe://example.org/workload
--- cert 2
        spiffe://example.org

```

## Why?

Placing claims inside x509 Certificates is not new. One such example is [SPIFFE](https://spiffe.io/). The SPIFFE spec
stores SPIFFE IDs in cryptographically verifiable documents called SVIDs. SPIFFE IDs are URIs
(example: `spiffe://somehost/somepath`) and can be stored in JWTs or x509 Certificates. SPIFFE IDs are stored as the
`sub` field of a JWT and as a URI SAN for x509 certificates. This go module is meant to support x509 SVIDs as well as
other x509 claims storage mechanisms.

One may ask: "why not use JWTs or any other signed document format?". x509 Certificates have benefits over other signed
documents. The main one being that secured client connections (i.e. mTLS) can be tied to private key that are stored
on hardare modules such as TPMs, HSMs, etc.
