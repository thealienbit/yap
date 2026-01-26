package crypto

import "testing"


func TestDeriveKey_Deterministic(t *testing.T) {
	params := Argon2Params{
		Memory: 64 * 1024,
		Iterations: 2,
		Parallelism: 1,
		KeyLength: 32,
	}

	password := []byte("correct horse battery staple")
	salt := []byte("1234567890abcdef")


	k1, err := DeriveKey(password, salt, params)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(password, salt, params)
	if err != nil {
		t.Fatal(err)
	}

	if string(k1) != string(k2) {
		t.Fatal("argon2 output not same")
	}
}

func TestDeriveKey_SaltMatters(t *testing.T) {
	params := Argon2Params{
		Memory: 64 * 1024,
		Iterations: 2,
		Parallelism: 1,
		KeyLength: 32,
	}

	password := []byte("password")
	salt1 := []byte("aaaaaaaaaaaaaaaa")
	salt2 := []byte("bbbbbbbbbbbbbbbb")

	k1, err := DeriveKey(password, salt1, params)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(password, salt2, params)
	if err != nil {
		t.Fatal(err)
	}

	if string(k1) == string(k2) {
		t.Fatal("different salt produced same key")
	}
}
