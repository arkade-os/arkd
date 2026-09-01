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

	got, count, err := normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || !bytes.Equal(got, want) {
		t.Fatalf("normalize() removed %d styles; got:\n%s", count, got)
	}
	again, count, err := normalize(got)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || !bytes.Equal(again, got) {
		t.Fatal("normalize() is not idempotent")
	}
}

func TestNormalizeHandlesReorderedAndInterveningFields(t *testing.T) {
	input := []byte("{\r\n" +
		"  \"parameters\": [\r\n" +
		"    {\r\n" +
		"      \"style\": \"simple\",\r\n" +
		"      \"name\": \"cursor\",\r\n" +
		"      \"schema\": {\"type\": \"string\"},\r\n" +
		"      \"description\": \"pagination cursor\",\r\n" +
		"      \"in\": \"query\"\r\n" +
		"    },\r\n" +
		"    {\r\n" +
		"      \"in\": \"query\",\r\n" +
		"      \"name\": \"limit\",\r\n" +
		"      \"schema\": {},\r\n" +
		"      \"style\": \"simple\"\r\n" +
		"    },\r\n" +
		"    {\"style\": \"simple\", \"in\": \"header\", \"name\": \"x-token\"}\r\n" +
		"  ],\r\n" +
		"  \"example\": \"\\\"in\\\": \\\"query\\\", \\\"style\\\": \\\"simple\\\"\"\r\n" +
		"}\r\n")
	want := []byte("{\r\n" +
		"  \"parameters\": [\r\n" +
		"    {\r\n" +
		"      \"name\": \"cursor\",\r\n" +
		"      \"schema\": {\"type\": \"string\"},\r\n" +
		"      \"description\": \"pagination cursor\",\r\n" +
		"      \"in\": \"query\"\r\n" +
		"    },\r\n" +
		"    {\r\n" +
		"      \"in\": \"query\",\r\n" +
		"      \"name\": \"limit\",\r\n" +
		"      \"schema\": {}\r\n" +
		"    },\r\n" +
		"    {\"style\": \"simple\", \"in\": \"header\", \"name\": \"x-token\"}\r\n" +
		"  ],\r\n" +
		"  \"example\": \"\\\"in\\\": \\\"query\\\", \\\"style\\\": \\\"simple\\\"\"\r\n" +
		"}\r\n")

	got, count, err := normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || !bytes.Equal(got, want) {
		t.Fatalf("normalize() removed %d styles; got:\n%s", count, got)
	}
}

func TestNormalizeRejectsInvalidJSON(t *testing.T) {
	if _, _, err := normalize([]byte(`{"in":"query",`)); err == nil {
		t.Fatal("normalize() accepted invalid JSON")
	}
}
