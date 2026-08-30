package main

import (
	"bytes"
	"testing"
)

func TestNormalize(t *testing.T) {
	input := []byte("{\n" +
		"  \"parameters\": [\n" +
		"    {\n" +
		"      \"in\": \"query\",\n" +
		"      \"style\": \"simple\",\n" +
		"      \"schema\": {}\n" +
		"    },\n" +
		"    {\n" +
		"      \"in\": \"query\",\n" +
		"      \"description\": \"topics\",\n" +
		"      \"style\": \"simple\",\n" +
		"      \"schema\": {}\n" +
		"    },\n" +
		"    {\n" +
		"      \"in\": \"path\",\n" +
		"      \"style\": \"simple\",\n" +
		"      \"schema\": {}\n" +
		"    }\n" +
		"  ]\n" +
		"}\n")
	want := []byte("{\n" +
		"  \"parameters\": [\n" +
		"    {\n" +
		"      \"in\": \"query\",\n" +
		"      \"schema\": {}\n" +
		"    },\n" +
		"    {\n" +
		"      \"in\": \"query\",\n" +
		"      \"description\": \"topics\",\n" +
		"      \"schema\": {}\n" +
		"    },\n" +
		"    {\n" +
		"      \"in\": \"path\",\n" +
		"      \"style\": \"simple\",\n" +
		"      \"schema\": {}\n" +
		"    }\n" +
		"  ]\n" +
		"}\n")

	got, count := normalize(input)
	if count != 2 || !bytes.Equal(got, want) {
		t.Fatalf("normalize() removed %d styles; got:\n%s", count, got)
	}
	again, count := normalize(got)
	if count != 0 || !bytes.Equal(again, got) {
		t.Fatal("normalize() is not idempotent")
	}
}
