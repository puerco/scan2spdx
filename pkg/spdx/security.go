package spdx

import "time"

type ExternalReference struct {
	TypedNode
	ExternalReferenceType string `json:"externalReferenceType"` // securityAdvisory",
	Locator               string `json:"locator"`               // https://nvd.nist.gov/vuln/detail/CVE-2020-28498"
}

type ExternalIdentifier struct {
	TypedNode
	ExternalIdentifierType string `json:"externalIdentifierType"` // "securityOther",
	Identifier             string `json:"identifier"`             // "GHSA-r9p9-mrjm-926w",
	IdentifierLocator      string `json:"identifierLocator"`      // "https://github.com/advisories/GHSA-r9p9-mrjm-926w"
}

type Vulnerability struct {
	Element
	Summary             string                `json:"summary"`     // "Use of a Broken or Risky Cryptographic Algorithm",
	Description         string                `json:"description"` // "The npm package `elliptic` before version 6.5.4 are vulnerable to Cryptographic Issues via the secp256k1 implementation in elliptic/ec/key.js. There is no check to confirm that the public key point passed into the derive function actually exists on the secp256k1 curve. This results in the potential for the private key used in this implementation to be revealed after a number of ECDH operations are performed.",
	Modified            time.Time             `json:"modified"`    // "2021-03-08T16:02:43Z",
	Published           time.Time             `json:"published"`   // "2021-03-08T16:06:50Z",
	ExternalIdentifiers *[]ExternalIdentifier `json:"externalIdentifiers"`
	ExternalReferences  *[]ExternalReference  `json:"externalReferences"`
}

type VulnAssessmentRelationship struct {
	AssessedElement    *[]string            `json:"assessedElement,omitempty"`
	SuppliedBy         *[]string            `json:"suppliedBy,omitempty"`
	ExternalReferences *[]ExternalReference `json:"externalReferences,omitempty"`
	PublishedTime      *time.Time           `json:"publishedTime,omitempty"`
	ModifiedTime       *time.Time           `json:"modifiedTime,omitempty"`
}

type CvssV3VulnAssessmentRelationship struct {
	Relationship
	VulnAssessmentRelationship
	Severity string  `json:"severity"`
	Score    float32 `json:"score"`
	Vector   string  `json:"vector"`
}

type CvssV2VulnAssessmentRelationship struct {
	Relationship
	VulnAssessmentRelationship
	Severity string  `json:"severity"`
	Score    float32 `json:"score"`
	Vector   string  `json:"vector"`
}
