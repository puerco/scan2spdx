package scan

import (
	"fmt"
	"io"
	"os"

	"github.com/puerco/scan2spdx/pkg/spdx"
)

type ScanFormatLabel string

const (
	FormatTrivy ScanFormatLabel = "trivy"
	FormatSnyk  ScanFormatLabel = "snyk"
	FormatGrype ScanFormatLabel = "grype"
)

func NewParser() *Parser {
	return &Parser{
		impl: &defaultParserImplementation{},
	}
}

type Parser struct {
	impl ParserImplementation
}

type ParserImplementation interface {
	CreateDocument() *spdx.Document
	DetectType(io.ReadSeeker) (ScanFormatLabel, error)
	ReadTrivy(io.ReadSeeker, *spdx.Document) error
	ReadSnyk(io.ReadSeeker, *spdx.Document) error
	ReadGrype(io.ReadSeeker, *spdx.Document) error
}

func (p *Parser) ParseFile(path string) (*spdx.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}

	doc, err := p.Read(f)
	if err != nil {
		return nil, fmt.Errorf("reading stream: %w", err)
	}

	return doc, nil
}

func (p *Parser) Read(scanData io.ReadSeeker) (doc *spdx.Document, err error) {
	format, err := p.impl.DetectType(scanData)
	if err != nil {
		return nil, fmt.Errorf("detecting scan format: %w", err)
	}

	doc = p.impl.CreateDocument()

	switch format {
	case FormatTrivy:
		err = p.impl.ReadTrivy(scanData, doc)
	case FormatGrype:
		err = p.impl.ReadGrype(scanData, doc)
	case FormatSnyk:
		err = p.impl.ReadSnyk(scanData, doc)
	}

	if err != nil {
		return nil, fmt.Errorf("reading %s scan: %w", format, err)
	}

	return doc, nil
}
