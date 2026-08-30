package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

const specs = "api-spec/openapi/swagger/*/v1/*.openapi.json"

var invalidQueryStyle = regexp.MustCompile(`(?m)(^[ \t]*"in": "query",\r?\n(?:^[ \t]*"description": [^\r\n]*,\r?\n)?)[ \t]*"style": "simple",\r?\n`)

func main() {
	paths, err := filepath.Glob(specs)
	if err != nil {
		log.Fatal(err)
	}
	if len(paths) == 0 {
		log.Fatalf("no specs match %s", specs)
	}

	total := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}

		fixed, count := normalize(data)
		if !json.Valid(fixed) {
			log.Fatalf("%s: invalid JSON", path)
		}
		if count > 0 {
			if err := os.WriteFile(path, fixed, 0o644); err != nil {
				log.Fatalf("%s: %v", path, err)
			}
		}
		total += count
	}

	fmt.Printf("Removed %d invalid query parameter style(s).\n", total)
}

func normalize(data []byte) ([]byte, int) {
	count := len(invalidQueryStyle.FindAll(data, -1))
	return invalidQueryStyle.ReplaceAll(data, []byte("${1}")), count
}
