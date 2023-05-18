package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/puerco/scan2spdx/pkg/scan"
)

func main() {
	fmt.Printf("Scan → SPDX v%s\n", "0.0.1")

	parser := scan.NewParser()
	doc, err := parser.ParseFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")
	if err := enc.Encode(doc); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
