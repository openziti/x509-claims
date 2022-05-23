package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/openziti/x509-claims"
	"net/url"
	"os"
)

// This command is provided as an example as well as a starting place for developers new to x509.Certificates.
func main() {
	if len(os.Args) != 2 {
		fmt.Printf("error: unexpected argument count, expected 1 got %d\n", len(os.Args)-1)
		printUsage()
		os.Exit(1)
	}

	if os.Args[1] == "-h" {
		printUsage()
		os.Exit(0)
	}

	fileInfo, err := os.Stat(os.Args[1])

	if err != nil {
		fmt.Printf("error: error reading file %s: %s\n", os.Args[1], err)
		os.Exit(1)
	}

	if fileInfo.IsDir() {
		fmt.Printf("error: error reading file %s: is not a file\n", os.Args[1])
		os.Exit(1)
	}

	fileBytes, err := os.ReadFile(os.Args[1])

	if err != nil {
		fmt.Printf("error: error reading file %s: %s\n", os.Args[1], err)
		os.Exit(1)
	}

	if len(fileBytes) == 0 {
		fmt.Printf("error: error reading file %s: %s", os.Args[1], "0 bytes read\n")
		os.Exit(1)
	}

	certs := pemToCertificates(fileBytes)

	if len(certs) == 0 {
		fmt.Print("error: error parsing certificates, expected at least 1 certificate got: 0\n")
		os.Exit(1)
	}

	fmt.Printf("...parsed %d certificates\n", len(certs))

	provider := x509_claims.ProviderBasic{
		Definitions: []x509_claims.Definition{
			&x509_claims.DefinitionLMP[*url.URL]{
				Locator: &x509_claims.LocatorSanUri{},
				Matcher: &x509_claims.MatcherScheme{Scheme: "spiffe"},
				Parser:  &x509_claims.ParserNoOp{},
			},
		},
	}

	for i, cert := range certs {
		fmt.Printf("\n--- cert %d\n", i+1)
		claims := provider.Claims(cert)

		for _, claim := range claims {
			fmt.Printf("\t%s", claim)
		}
	}
}

// decodeAll accepts a byte array of PEM encoded data returns PEM blocks of data.
// The blocks will be in the order that they are provided in the original bytes.
func decodeAll(pemBytes []byte) []*pem.Block {
	var blocks []*pem.Block
	if len(pemBytes) == 0 {
		return blocks
	}
	b, rest := pem.Decode(pemBytes)

	for b != nil {
		blocks = append(blocks, b)
		b, rest = pem.Decode(rest)
	}
	return blocks
}

// pemToCertificates accepts PEM bytes and returns an array of x509.Certificate. Any blocks that
// cannot be parsed as a x509.Certificate is discard. Certificate are returned to the
// order they are encountered in the PEM string.
func pemToCertificates(pem []byte) []*x509.Certificate {
	pemBytes := pem
	certs := make([]*x509.Certificate, 0)
	for _, block := range decodeAll(pemBytes) {
		if block.Type == "CERTIFICATE" {
			xcerts, err := x509.ParseCertificate(block.Bytes)
			if err == nil && xcerts != nil {
				certs = append(certs, xcerts)
			}
		}
	}
	return certs
}

func printUsage() {
	fmt.Printf("\n")
	fmt.Printf("This program is an example implementation of x509-claims. It parses out SPIFFE IDs from x509 Certificates.\n\n")
	fmt.Printf("Usage:\n")
	fmt.Printf("\tx509-claims [-h] <cert-pem-file>\n\n")
}
