package x509claims

import "strings"

type Parser interface {
	Parse(value string) []string
}

var _ Parser = &ParserNoOp{}

type ParserNoOp struct{}

func (_ *ParserNoOp) Parse(value string) []string {
	return []string{value}
}

var _ Parser = &ParserSplit{}

type ParserSplit struct {
	Separator string
}

func (p *ParserSplit) Parse(value string) []string {
	return strings.Split(value, p.Separator)
}
