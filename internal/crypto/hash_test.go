package crypto
import "testing"

func TestHash_Deterministic(t *testing.T) {
	data := []byte("hello world")

	h1, err := Hash(data)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash(data)
	if err != nil {
		t.Fatal(err)
	}

	if string(h1) != string(h2) {
		t.Fatal("hash not deterministic")
	}
}

func TestHash_ChangesOnInput(t *testing.T) {
	h1, _ := Hash([]byte("a"))
	h2, _ := Hash([]byte("b"))

	if string(h1) == string(h2) {
		t.Fatal("different inputs produced same hash")
	}
}

func TestHash_Length(t *testing.T) {
	h1, _ := Hash([]byte("x"))
	if len(h1) != HashSize {
		t.Fatalf("expected %d-byte hash, got %d", HashSize, len(h1))
	}
}
