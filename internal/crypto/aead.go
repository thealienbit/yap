package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	XChaChaKeySize = 32
	XChaChaNonceSize = chacha20poly1305.NonceSizeX
)

// encrypts plain text using XChaCha20-Poly1305
func Encrypt(
	key []byte,
	nonce []byte,
	plaintext []byte,
	aad []byte,
) ([]byte, error) {
	if len(key) != XChaChaKeySize {
		return nil, fmt.Errorf("Invalid key length")
	}

	if len(nonce) != XChaChaNonceSize {
		return nil, fmt.Errorf("Invalid nonce length")
	}


	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead init failed: %w", err)
	}

	cipherText := aead.Seal(nil, nonce, plaintext, aad)
	return cipherText, nil
}

func Decrypt(
	key []byte,
	nonce []byte,
	cipherText []byte,
	aad []byte,
) ([]byte, error) {
	if len(key) != XChaChaKeySize {
		return  nil, fmt.Errorf("Invalid key length")
	}

	if len(nonce) != XChaChaNonceSize {
		return nil, fmt.Errorf("Invalid nonce size")
	}


	aead, err :=  chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead init failed")
	}

	plainText, err := aead.Open(nil, nonce, cipherText, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	return plainText, nil
}
