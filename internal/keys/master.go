package keys

import (
	"fmt"
	"yap/internal/crypto"
)


const (
	DefaultArgonMemory = 128 * 1024
	DefaultArgonIterations = 3
	DefaultArgonParallelism = 4
	DefaultArgonKeyLength = 32
)

func GenerateSalt(rng crypto.RNG, size int) ([]byte, error) {
	if size < 16 || size > 32 {
		return nil, fmt.Errorf("salt size must be 16-32 bytes")
	}

	salt := make([]byte, size)
	if _, err := rng.Read(salt); err != nil {
		return  nil, err
	}

	return salt, nil
}

func DeriveMasterKey(
	password []byte,
	salt[] byte,
	params crypto.Argon2Params,
) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("master password cannot be empty")
	}

	// Enforce safe lower bounds
	if params.Memory < DefaultArgonMemory {
		return nil, fmt.Errorf("argon2 memory too low")
	}
	if params.Iterations < DefaultArgonIterations {
		return nil, fmt.Errorf("argon2 iterations too low")
	}
	if params.KeyLength < DefaultArgonKeyLength {
		return nil, fmt.Errorf("unexpected masterk key length")
	}
	if params.Parallelism < DefaultArgonParallelism {
		return nil, fmt.Errorf("argon2 parallelism too low")
	}

	key, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return nil, fmt.Errorf("argon2id derivation failed: %w", err)
	}

	return key, nil
}


func DefaultArgon2Params() crypto.Argon2Params {
	return  crypto.Argon2Params{
		Memory: DefaultArgonMemory,
		Iterations: DefaultArgonIterations,
		Parallelism: DefaultArgonParallelism,
		KeyLength: DefaultArgonKeyLength,
	}
}
