package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	fmt.Printf("Scan → SPDX v%s\n", "v0.0.1")
	json.Unmarshal([]byte{}, nil)
}
