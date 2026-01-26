package crypto

import "testing"


func TestSecureRNG_Read(t *testing.T) {
	rng := SecureRNG{}
	buf := make([]byte, 32)


	n, err := rng.Read(buf)

	if err != nil {
		t.Fatalf("rng.Read failed: %v", err)
	}

	if n != len(buf) {
		t.Fatalf("expected %d bytes but got %d", len(buf), n)
	}

	allZero := true
	for _, b:= range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("rng returned all-zero buffer")
	}
}
