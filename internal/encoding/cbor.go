package encoding

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	encOpts := cbor.EncOptions{
		// RFC 8949 canonical sorting
		Sort: cbor.SortCanonical,
		// deterministic float encoding
		ShortestFloat: cbor.ShortestFloat16,
		IndefLength: cbor.IndefLengthForbidden,
	}

	var err error
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(fmt.Errorf("cbor encoder init failed :%w", err))
	}

	decOpts := cbor.DecOptions{
		// reject duplicate keys
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
		// no streaming / partial items
		IndefLength: cbor.IndefLengthForbidden,
		// semantic tags not allowed 
		TagsMd: cbor.TagsForbidden,
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(fmt.Errorf("cbor decoder init failed :%w", err))
	}
}

// MarshalCanonical encodes v into canonical CBOR bytes.
//
// Guarantees:
// - Deterministic output
// - Sorted map keys
// - No indefinite-length items
func MarshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer

	enc := encMode.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("cbor encode failed: %w", err)
	}

	return  buf.Bytes(), nil
}

// UnmarshalStrict decodes CBOR bytes into v using strict rules.
//
// Guarantees:
// - Rejects malformed CBOR
// - Rejects duplicate map keys
// - Rejects tags and indefinite-length items
func UnmarshalStrict(data []byte, v any) error {
	r := bytes.NewReader(data)
	dec := decMode.NewDecoder(r)

	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("cbor decode failed: %w", err)
	}
	
	if r.Len() > 0 {
		return fmt.Errorf("cbor decode failed: trailing data")
	}
	
	return nil
}
