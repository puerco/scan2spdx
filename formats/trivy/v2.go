package trivy

import "time"

type Report struct {
	ArtifactName string
	ArtifactType string
	Metadata     Metadata
	Results      []Result
}

type Result struct {
	Class           string
	Target          string
	Type            string
	Vulnerabilities []Vulnerability
}

type Metadata struct {
	ImageID     string // digest
	RepoTags    []string
	RepoDigests []string
}

type Vulnerability struct {
	ID               string // `json:"VulnerabilityID"`  // CVE-2011-3374
	PkgID            string // "apt@2.2.4",
	PkgName          string // "apt",
	InstalledVersion string // "2.2.4",
	Layer            struct {
		Digest string // "sha256:9e3ea8720c6de96cc9ad544dddc695a3ab73f5581c5d954e0504cc4f80fb5e5c",
		DiffID string // "sha256:8553b91047dad45bedc292812586f1621e0a464a09a7a7c2ce6ac5f8ba2535d7"
	}
	SeveritySource string // "debian",
	PrimaryURL     string // "https://avd.aquasec.com/nvd/cve-2011-3374",
	DataSource     struct {
		ID   string // "debian",
		Name string // "Debian Security Tracker",
		URL  string // "https://salsa.debian.org/security-tracker-team/security-tracker"
	}
	Title            string // "It was found that apt-key in apt, all versions, do not correctly valid ...",
	Description      string // "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
	Severity         string // "LOW",
	CweIDs           []string
	CVSS             map[string]CVSS
	References       []string  // "https://access.redhat.com/security/cve/cve-2011-3374",
	PublishedDate    time.Time //  "2019-11-26T00:15:00Z",
	LastModifiedDate time.Time //  "2021-02-09T16:08:00Z"
}

type CVSS struct {
	V2Vector string  // "AV:N/AC:M/Au:N/C:N/I:P/A:N",
	V3Vector string  // "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
	V2Score  float32 // 4.3,
	V3Score  float32 // 3.7
}
