package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/puerco/scan2spdx/formats/trivy"
	"github.com/puerco/scan2spdx/pkg/spdx"
)

type defaultParserImplementation struct{}

func (di *defaultParserImplementation) CreateDocument() *spdx.Document {
	doc := &spdx.Document{
		Element:      spdx.Element{},
		RootElements: []string{},
		Elements:     []interface{}{},
	}
	return doc
}

func (di *defaultParserImplementation) DetectType(io.ReadSeeker) (ScanFormatLabel, error) {
	return FormatTrivy, nil
}

func genID() string {
	return fmt.Sprintf("urn:uuid:%s", uuid.New())
}

func (di *defaultParserImplementation) ReadTrivy(scanStream io.ReadSeeker, doc *spdx.Document) error {
	scanData := &trivy.Report{}
	dec := json.NewDecoder(scanStream)
	if err := dec.Decode(scanData); err != nil {
		return fmt.Errorf("scanning json report: %w", err)
	}

	packageID := genID()
	doc.Elements = append(doc.Elements, spdx.Package{
		Element: spdx.Element{
			ID: packageID,
			TypedNode: spdx.TypedNode{
				Type: "Package",
			},
		},
		Name:             "",
		Version:          "",
		DownloadLocation: "",
		SourceInfo:       "",
	})

	doc.Elements = append(doc.Elements, spdx.Relationship{
		Element:          spdx.Element{},
		RelationshipType: "contains",
		From:             packageID,
		To:               []string{},
		StartTime:        time.Time{},
	})

	for _, r := range scanData.Results {
		if r.Vulnerabilities == nil {
			continue
		}

		for _, v := range r.Vulnerabilities {
			vuln := spdx.Vulnerability{
				Element: spdx.Element{
					ID:        fmt.Sprintf("urn:uuid:%s", uuid.New()),
					TypedNode: spdx.TypedNode{},
				},
				Summary:     v.Title,
				Description: v.Description,
				Modified:    v.PublishedDate,
				Published:   v.LastModifiedDate,
			}
			if len(v.References) > 0 {
				refs := []spdx.ExternalReference{}
				for _, u := range v.References {
					refs = append(refs, spdx.ExternalReference{
						TypedNode: spdx.TypedNode{
							Type: "ExternalReference",
						},
						ExternalReferenceType: "securityAdvisory",
						Locator:               u,
					})
				}
				vuln.ExternalReferences = &refs
			}

			ids := []spdx.ExternalIdentifier{
				{
					TypedNode: spdx.TypedNode{
						Type: "ExternalIdentifier",
					},
					ExternalIdentifierType: "securityOther",
					Identifier:             v.ID,
					IdentifierLocator:      v.PrimaryURL,
				},
			}
			vuln.ExternalIdentifiers = &ids
			curTo := doc.Elements[1].(spdx.Relationship).To
			curTo = append(curTo, vuln.ID)
			doc.Elements[1].(spdx.Relationship).To = curTo
			doc.Elements = append(doc.Elements, vuln)

			// Assessments
			if v.CVSS != nil && len(v.CVSS) > 0 {
				for pv, cvss := range v.CVSS {
					if cvss.V3Score > 0 && cvss.V3Vector != "" {
						rel := spdx.CvssV3VulnAssessmentRelationship{
							Relationship: spdx.Relationship{
								Element: spdx.Element{
									ID: genID(),
									TypedNode: spdx.TypedNode{
										Type: "CvssV3VulnAssessmentRelationship",
									},
								},
								RelationshipType: "hasCvssV3AssessmentFor",
								From:             vuln.ID,
								To:               []string{packageID},
								StartTime:        time.Time{},
							},
							Severity:        v.Severity,
							Score:           cvss.V3Score,
							Vector:          cvss.V3Vector,
							AssessedElement: []string{}, // not having an SBOM makes it impossible to fill this
							SuppliedBy:      []string{},
							// ExternalReferences: &[]spdx.Excccccbctdtlfjrninhblhnvgfujlfcrhitldhekgrejh
							PublisedTime: &vuln.Published,
						}
					}
				}
			}

		}
	}
	return nil
}

func (di *defaultParserImplementation) ReadSnyk(io.ReadSeeker, *spdx.Document) error {
	return errors.New("not implemented yet")
}

func (di *defaultParserImplementation) ReadGrype(io.ReadSeeker, *spdx.Document) error {
	return errors.New("not implemented yet")
}
