package main

import (
	"math/big"
	"strings"
	"testing"
	"unicode"
)

func TestCalculateShannonEntropy(t *testing.T) {
	data := []byte("AAAAA")
	entropy := CalculateShannonEntropy(data)
	if entropy != 0 {
		t.Errorf("Expected 0 entropy for repeating bytes, got %f", entropy)
	}

	data2 := []byte("abcdefg")
	entropy2 := CalculateShannonEntropy(data2)
	if entropy2 < 2.5 {
		t.Errorf("Expected higher entropy for unique chars, got %f", entropy2)
	}
}

func TestRot13(t *testing.T) {
	solver := NewSolver()
	input := "cvpbPGS{guvf_vf_n_g3fg}"
	expected := "picoCTF{this_is_a_t3st}"

	result := solver.Rot13(input)
	if result.DecodedData != expected {
		t.Errorf("Rot13 failed. Expected %s, got %s", expected, result.DecodedData)
	}
}

func TestCaesarBruteForce(t *testing.T) {
	solver := NewSolver()
	input := "qjdpDUG"

	result := solver.BruteForceCaesar(input)
	if !result.Success {
		t.Errorf("Caesar Brute Force failed to find flag")
	}

	if result.DecodedData != "picoCTF" {
		t.Errorf("Caesar Decoded Data mismatch. Got %s", result.DecodedData)
	}
}

func TestParseRSA(t *testing.T) {
	input := "N: 12345\ne: 3\nC = 0x1a"
	params := ParseRSA(input)

	if params.N == nil || params.N.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("Failed to parse N correctly. Got %v", params.N)
	}
	if params.E == nil || params.E.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("Failed to parse E correctly. Got %v", params.E)
	}
	if params.C == nil || params.C.Cmp(big.NewInt(0x1a)) != 0 {
		t.Errorf("Failed to parse C correctly. Got %v", params.C)
	}
}

func TestSmallExponentAttack(t *testing.T) {
	params := &RSAParams{
		N: big.NewInt(100000),
		E: big.NewInt(3),
		C: big.NewInt(74088),
	}

	decodedResult := SolveRSA(params, false) // Online false

	if !decodedResult.Success {
		t.Errorf("Small Exponent Attack failed")
	}
	if decodedResult.DecodedData != "*" {
		t.Errorf("Decoded data mismatch. Expected '*', got %v", decodedResult.DecodedData)
	}
}

func TestXORSolver(t *testing.T) {
	// Encrypt "picoCTF{xor}" with key 0x42 ('B')
	plaintext := "picoCTF{xor}"
	key := byte(0x42)
	input := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		input[i] = plaintext[i] ^ key
	}

	res, k, score := SolveSingleByteXOR(input)

	if k != key {
		t.Errorf("XOR Solver failed. Expected key 0x%02X, got 0x%02X", key, k)
	}
	if res != plaintext {
		t.Errorf("XOR Solver failed. Expected %s, got %s", plaintext, res)
	}
	if score < 1000.0 {
		t.Errorf("XOR Solver failed to identify flag magic. Score: %f", score)
	}
}

func TestVigenereSolver(t *testing.T) {
	// Encrypt "picoCTF{vig}" with "PICO"
	// p(15) + P(15) = 30%26 = 4 -> e
	// ... logic check
	// Using manual encrypt for test input: "ewqeQFVuigm" (rough guess)
	// Let's reverse eng:
	// P(15) - P(15) = 0 a
	// I(8) - I(8) = 0 a ... wait PICO PICO
	// Let's trust the decrypt function works and just use a known text from a generator or self-encrypt.

	// Self-encrypt using code being tested? No, implementation might be wrong.
	// Manual:
	// Plain: FLAG
	// Key:   PICO
	// F(5)+P(15) = 20 (U)
	// L(11)+I(8) = 19 (T)
	// A(0)+C(2)  = 2  (C)
	// G(6)+O(14) = 20 (U)
	// Cipher: UTCU

	// input := "UTCU" // for "FLAG"

	// Our solver looks for "picoCTF{" prefix to win.
	// So we need to encrypt "picoCTF{...}" with "PICO".
	// p+P = e
	// i+I = q
	// c+C = e
	// o+O = c
	// C+P = R
	// T+I = B
	// F+C = H
	// {+O = ... { is not letter. Solver skips non-letters.

	// "eqecRBH{...}"

	// Wait, our Vigenere implementation (standard):
	/*
		if !unicode.IsLetter(r) {
			result.WriteRune(r)
			continue
		}
	*/

	// We need to feed it text that decrypts to "picoCTF{...}"

	// Let's just create a helper test that forces a "win" by reverse encrypting properly.
	pt := "picoCTF{test}"
	key := "PICO"

	// Encrypt PT with Key
	var ct strings.Builder
	ki := 0
	kRunes := []rune(key)
	for _, r := range pt {
		if !unicode.IsLetter(r) {
			ct.WriteRune(r)
			continue
		}
		shift := kRunes[ki%len(kRunes)] - 'A'
		base := 'a'
		if unicode.IsUpper(r) {
			base = 'A'
		}
		ct.WriteRune(base + (r-base+shift)%26)
		ki++
	}

	// Now attempt solve
	res, k := SolveVigenere(ct.String())

	if k != "PICO" {
		t.Errorf("Vigenere Solver failed. Expected key PICO, got %s", k)
	}
	if res != pt {
		t.Errorf("Vigenere Solver failed. Expected %s, got %s", pt, res)
	}
}
