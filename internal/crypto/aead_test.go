package crypto
import "testing"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, XChaChaKeySize)
	nonce := make([]byte, XChaChaNonceSize)
	aad := []byte("associated-data")
	plainText := []byte("secret message")

	rng := SecureRNG{}
	rng.Read(key)
	rng.Read(nonce)

	ct, err := Encrypt(key, nonce, plainText, aad)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := Decrypt(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}

	if string(pt) != string(plainText) {
		t.Fatal("decrypted plaintext mismatch")
	}
}

func TestDecrypt_FailsOnAADMismatch(t *testing.T) {
	key := make([]byte, XChaChaKeySize)
	nonce := make([]byte, XChaChaNonceSize)
	rng := SecureRNG{}
	rng.Read(key)
	rng.Read(nonce)

	ct, _ := Encrypt(key, nonce, []byte("data"), []byte("aad1"))
	_, err := Decrypt(key, nonce, ct, []byte("aad2"))
	if err == nil {
		t.Fatal("expected decryption failure on AAD mismatch")
	}
}
