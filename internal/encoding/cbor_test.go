package encoding

import (
	"bytes"
	"testing"
)


func TestMarshalCanonical_Deterministic(t *testing.T) {
	input := map[string]any{
		"b": 2,
		"a": 1,
	}

	b1, err := MarshalCanonical(input)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := MarshalCanonical(input)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b1, b2) {
		t.Fatal("canonical CBOR encoding is not deterministic")
	}
}

func TestMarshalCanonical_SortedMapKeys(t *testing.T) {
	m1 := map[string]any{
		"a": 1,
		"b": 2,
		"c": 3,
	}

	m2 := map[string]any{
		"c": 3,
		"b": 2,
		"a": 1,
	}

	b1, err := MarshalCanonical(m1)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := MarshalCanonical(m2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b1, b2) {
		t.Fatal("map key ordering affected canonical encoding")
	}
}

func TestUnmarshalStrict_RejectsDuplicateKeys(t *testing.T) {
	// CBOR map with duplicate key "a"
	// a1 61 61 01 61 61 02
	dupKeyCBOR := []byte{
		0xa2,       // map(2)
		0x61, 0x61, // "a"
		0x01,       // 1
		0x61, 0x61, // "a"
		0x02,       // 2
	}

	var out map[string]any
	err := UnmarshalStrict(dupKeyCBOR, &out)
	if err == nil {
		t.Fatal("expected error on duplicate CBOR map keys")
	}
}

func TestUnmarshalStrict_RejectsMalformedInput(t *testing.T) {
	// Truncated CBOR (claims map, but no content)
	badCBOR := []byte{0xa1}

	var out map[string]any
	err := UnmarshalStrict(badCBOR, &out)
	if err == nil {
		t.Fatal("expected error on malformed CBOR")
	}
}

func TestUnmarshalStrict_RejectsTrailingData(t *testing.T) {
	valid, err := MarshalCanonical(map[string]int{"a": 1})
	if err != nil {
		t.Fatal(err)
	}

	// Append junk bytes
	data := append(valid, 0xff, 0xff)

	var out map[string]int
	err = UnmarshalStrict(data, &out)
	if err == nil {
		t.Fatal("expected error due to trailing CBOR data")
	}
}

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	type sample struct {
		A int    `cbor:"a"`
		B string `cbor:"b"`
	}

	in := sample{
		A: 42,
		B: "hello",
	}

	data, err := MarshalCanonical(in)
	if err != nil {
		t.Fatal(err)
	}

	var out sample
	if err := UnmarshalStrict(data, &out); err != nil {
		t.Fatal(err)
	}

	if in != out {
		t.Fatalf("round-trip mismatch: %+v != %+v", in, out)
	}
}
