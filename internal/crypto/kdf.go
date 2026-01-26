package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory uint32
	Iterations uint32
	Parallelism uint8
	KeyLength uint32
}


func DeriveKey(
	password []byte,
	salt []byte,
	params Argon2Params,
) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt too short")
	}

	key := argon2.IDKey(
		password,
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	if len(key) != int(params.KeyLength) {
		return nil, fmt.Errorf("argon2 produced wrong key length")
	}


	return key, nil
}
