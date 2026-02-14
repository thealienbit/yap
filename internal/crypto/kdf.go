/*
* KDF - Key Derivation Function
*
* Using Argon2id for KDF
*
* Argon2i: (Interactive) Designed to resist side channel attacks, accesses memory
* in a password independent order, safe for situations where attacker 
* might be able to monitor memory timeing
*
* Argon2d: (Data-Dependent) Designed to resist GPU/ASIC cracking attacks, accesses
* memory in a password dependent order , which makes is harder to guess password 
* using hardware
*
* Argon2id: Uses best of both worlds. Uses first pass over memory from Argon2i and
* subsequent passes using the Argon2d
*
* Why not traditional algorithms like SHA256 ?
* SHA256 is extremely fast, which is a disadvantage for password storage because,
* attacker with a powerful GPU can guess billions of SHA256 hashes per second
* Argon2id fights this with three main "cost factors
* 1) memory hardness: You can specify exactly how much RAM the algorithm must use
* 	(e.g., 64MB or 1GB). This makes it incredibly expensive for attackers to build
* 	custom hardware to crack passwords at scale
* 2) Time Cost ($t$): You can define how many iterations the algorithm performs, 
* 	forcing a delay that frustrates "brute-force" attempts
* 3) Parallelism ($p$): It can be tuned to use multiple CPU cores, 
* 	allowing legitimate servers to compute the hash quickly while still remaining 
* 	"heavy" for an attacker
*/
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
