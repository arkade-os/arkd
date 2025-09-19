package e2e_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// findNthCapture returns the Nth match's first capture group content.
func findNthCapture(re *regexp.Regexp, s string, n int) string {
	matches := re.FindAllStringSubmatch(s, -1)
	if len(matches) >= n && len(matches[n-1]) >= 2 {
		return matches[n-1][1]
	}
	return ""
}

// parseBraceKV parses "{A:1 B:2.3 C:hello}" into map[string]string.
func parseBraceKV(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = s[1 : len(s)-1]
	}
	parts := strings.Fields(s)
	out := map[string]string{}
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out[kv[0]] = kv[1]
	}
	return out, nil
}

// parseMapOfStructs parses 'map[key:{A:1 B:2} key2:{A:3}]' into map[key]map[field]value.
func parseMapOfStructs(s string) (map[string]map[string]string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "map[") && strings.HasSuffix(s, "]") {
		s = s[4 : len(s)-1]
	}
	out := map[string]map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			break
		}
		col := strings.IndexByte(s, ':')
		if col <= 0 {
			break
		}
		key := s[:col]
		rest := strings.TrimLeft(s[col+1:], " ")
		if rest == "" || rest[0] != '{' {
			break
		}
		block, consumed := takeBraceBlock(rest)
		if consumed == 0 {
			break
		}
		kv, _ := parseBraceKV(block)
		out[key] = kv
		s = strings.TrimLeft(rest[consumed:], " ")
	}
	return out, nil
}

// takeBraceBlock returns the brace-delimited block "{}" and bytes consumed.
func takeBraceBlock(s string) (string, int) {
	if len(s) == 0 || s[0] != '{' {
		return "", 0
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[:i+1], i + 1
			}
		}
	}
	return "", 0
}

func atoi(s string) int {
	f, _ := strconv.ParseFloat(s, 64)
	return int(f)
}
func atof(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}
func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
