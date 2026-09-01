package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
)

const specs = "api-spec/openapi/swagger/*/v1/*.openapi.json"

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

		fixed, count, err := normalize(data)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
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

type span struct {
	start int
	end   int
}

type objectMember struct {
	key         string
	prefixStart int
	valueStart  int
	valueEnd    int
	comma       int
}

type jsonScanner struct {
	data     []byte
	removals []span
}

// normalize parses the JSON structure and removes only style: simple members
// belonging to query parameter objects. It applies byte-range edits to the
// original document so generated key ordering and whitespace remain unchanged.
func normalize(data []byte) ([]byte, int, error) {
	if !json.Valid(data) {
		return nil, 0, fmt.Errorf("invalid JSON")
	}

	scanner := jsonScanner{data: data}
	end, err := scanner.parseValue(scanner.skipSpace(0))
	if err != nil {
		return nil, 0, err
	}
	if scanner.skipSpace(end) != len(data) {
		return nil, 0, fmt.Errorf("unexpected data after JSON value")
	}

	sort.Slice(scanner.removals, func(i, j int) bool {
		return scanner.removals[i].start > scanner.removals[j].start
	})
	fixed := append([]byte(nil), data...)
	for _, removal := range scanner.removals {
		fixed = append(fixed[:removal.start], fixed[removal.end:]...)
	}

	return fixed, len(scanner.removals), nil
}

func (s *jsonScanner) parseValue(start int) (int, error) {
	start = s.skipSpace(start)
	if start >= len(s.data) {
		return 0, fmt.Errorf("unexpected end of JSON")
	}

	switch s.data[start] {
	case '{':
		return s.parseObject(start)
	case '[':
		return s.parseArray(start)
	case '"':
		return s.parseString(start)
	default:
		end := start
		for end < len(s.data) && !isValueDelimiter(s.data[end]) {
			end++
		}
		if end == start {
			return 0, fmt.Errorf("unexpected byte %q at offset %d", s.data[start], start)
		}
		return end, nil
	}
}

func (s *jsonScanner) parseObject(start int) (int, error) {
	pos := start + 1
	members := make([]objectMember, 0)

	for {
		prefixStart := pos
		pos = s.skipSpace(pos)
		if pos >= len(s.data) {
			return 0, fmt.Errorf("unterminated object at offset %d", start)
		}
		if s.data[pos] == '}' {
			s.recordInvalidQueryStyles(members)
			return pos + 1, nil
		}
		if s.data[pos] != '"' {
			return 0, fmt.Errorf("expected object key at offset %d", pos)
		}

		keyStart := pos
		keyEnd, err := s.parseString(keyStart)
		if err != nil {
			return 0, err
		}
		var key string
		if err := json.Unmarshal(s.data[keyStart:keyEnd], &key); err != nil {
			return 0, fmt.Errorf("decode object key at offset %d: %w", keyStart, err)
		}

		pos = s.skipSpace(keyEnd)
		if pos >= len(s.data) || s.data[pos] != ':' {
			return 0, fmt.Errorf("expected colon after object key at offset %d", keyStart)
		}
		valueStart := s.skipSpace(pos + 1)
		valueEnd, err := s.parseValue(valueStart)
		if err != nil {
			return 0, err
		}

		pos = s.skipSpace(valueEnd)
		comma := -1
		if pos < len(s.data) && s.data[pos] == ',' {
			comma = pos
			pos++
		} else if pos >= len(s.data) || s.data[pos] != '}' {
			return 0, fmt.Errorf("expected comma or object end at offset %d", pos)
		}

		members = append(members, objectMember{
			key:         key,
			prefixStart: prefixStart,
			valueStart:  valueStart,
			valueEnd:    valueEnd,
			comma:       comma,
		})
	}
}

func (s *jsonScanner) parseArray(start int) (int, error) {
	pos := start + 1
	for {
		pos = s.skipSpace(pos)
		if pos >= len(s.data) {
			return 0, fmt.Errorf("unterminated array at offset %d", start)
		}
		if s.data[pos] == ']' {
			return pos + 1, nil
		}

		var err error
		pos, err = s.parseValue(pos)
		if err != nil {
			return 0, err
		}
		pos = s.skipSpace(pos)
		if pos < len(s.data) && s.data[pos] == ',' {
			pos++
			continue
		}
		if pos >= len(s.data) || s.data[pos] != ']' {
			return 0, fmt.Errorf("expected comma or array end at offset %d", pos)
		}
	}
}

func (s *jsonScanner) parseString(start int) (int, error) {
	for pos := start + 1; pos < len(s.data); pos++ {
		switch s.data[pos] {
		case '\\':
			pos++
			if pos >= len(s.data) {
				return 0, fmt.Errorf("unterminated escape at offset %d", start)
			}
		case '"':
			return pos + 1, nil
		}
	}
	return 0, fmt.Errorf("unterminated string at offset %d", start)
}

func (s *jsonScanner) recordInvalidQueryStyles(members []objectMember) {
	isQueryParameter := false
	styleIndexes := make([]int, 0, 1)
	for i, member := range members {
		if member.key == "in" && s.stringValue(member) == "query" {
			isQueryParameter = true
		}
		if member.key == "style" && s.stringValue(member) == "simple" {
			styleIndexes = append(styleIndexes, i)
		}
	}
	if !isQueryParameter {
		return
	}

	for _, i := range styleIndexes {
		if i+1 < len(members) {
			s.removals = append(s.removals, span{
				start: members[i].prefixStart,
				end:   members[i+1].prefixStart,
			})
			continue
		}
		if i > 0 && members[i-1].comma >= 0 {
			s.removals = append(s.removals, span{
				start: members[i-1].comma,
				end:   members[i].valueEnd,
			})
		}
	}
}

func (s *jsonScanner) stringValue(member objectMember) string {
	if member.valueStart >= member.valueEnd || s.data[member.valueStart] != '"' {
		return ""
	}
	var value string
	if err := json.Unmarshal(s.data[member.valueStart:member.valueEnd], &value); err != nil {
		return ""
	}
	return value
}

func (s *jsonScanner) skipSpace(pos int) int {
	for pos < len(s.data) {
		switch s.data[pos] {
		case ' ', '\t', '\r', '\n':
			pos++
		default:
			return pos
		}
	}
	return pos
}

func isValueDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', ',', ']', '}':
		return true
	default:
		return false
	}
}
