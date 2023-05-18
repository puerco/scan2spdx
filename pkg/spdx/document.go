package spdx

import "time"

type TypedNode struct {
	Type string `json:"@type"`
}

type Element struct {
	ID string `json:"@id"`
	TypedNode
}

type Document struct {
	Element
	RootElements []string `json:"rootElements"`
	Elements     []interface{}
}

type CreationInfo struct {
	SpecVersion string    `json:"specVersion"` //  "3.0.0-rc.1",
	Created     time.Time `json:"created"`
	Profile     []string  `json:"profile"`
	DataLicense string    `json:"dataLicense"`
	CreatedBy   string    `json:"createdBy"`
}

type Package struct {
	Element
	Name             string `json:"name"`
	Version          string `json:"packageVersion"`
	DownloadLocation string `json:"downloadLocation"`
	PackageUrl       string `json:"packageUrl"`
	HomePage         string `json:"homePage"`
	SourceInfo       string `json:"sourceInfo"`
}

type Relationship struct {
	Element
	RelationshipType string    `json:"relationshipType"`
	From             string    `json:"from"`
	To               []string  `json:"to"`
	StartTime        time.Time `json:"startTime"`
}
