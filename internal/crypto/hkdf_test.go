package crypto
import "testing"

func TestHKDFExpand_DomainSeparation(t *testing.T) {
	prk := []byte("this-is-a-test-prk")

	k1, err := HKDFExpand(prk, []byte("context-1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := HKDFExpand(prk, []byte("context-2"), 32)
	if err != nil {
		t.Fatal(err)
	}

	if string(k1) == string(k2) {
		t.Fatal("hkdf info did not separate keys")
	}
}

func TestHKDFExpand_Length(t *testing.T) {
	prk := []byte("prk")

	key, err := HKDFExpand(prk, []byte("ctx"), 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 64 {
		t.Fatalf("expected 64 bytes, got %d",len(key))
	}
}
