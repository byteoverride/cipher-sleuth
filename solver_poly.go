package main

import (
	"strings"
	"unicode"
)

// Common English letter frequency (simplified) for scoring
// E, T, A, O, I, N, S, H, R, D, L, U
var englishFreq = map[byte]float64{
	'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
	's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'u': 2.8,
	' ': 15.0, // Space is very common
}

// SolveSingleByteXOR attempts to break single-byte XOR
func SolveSingleByteXOR(input []byte) (string, byte, float64) {
	bestScore := 0.0
	bestRes := ""
	bestKey := byte(0)

	for k := 0; k < 256; k++ {
		key := byte(k)
		decoded := make([]byte, len(input))
		score := 0.0

		// XOR and Score
		for i, b := range input {
			dec := b ^ key
			decoded[i] = dec

			// Scoring
			lower := byte(unicode.ToLower(rune(dec)))
			if val, ok := englishFreq[lower]; ok {
				score += val
			} else if dec < 32 || dec > 126 {
				// Penalize non-printable chars heavily
				if dec != '\n' && dec != '\r' && dec != '\t' {
					score -= 10.0
				}
			}
		}

		resStr := string(decoded)

		// Magic Check: Instant Win
		if strings.Contains(resStr, "picoCTF{") || strings.Contains(resStr, "HTB{") {
			return resStr, key, 1000.0 // Max confidence
		}

		if score > bestScore {
			bestScore = score
			bestRes = resStr
			bestKey = key
		}
	}

	return bestRes, bestKey, bestScore
}

// SolveVigenere attempts a dictionary attack on Vigenère cipher
func SolveVigenere(input string) (string, string) {
	// Embedded dictionary
	keys := []string{"CYLAB", "PICO", "FLAG", "ADMIN", "PASSWORD"}

	for _, key := range keys {
		decoded := vigenereDecrypt(input, key)

		// Check for flag prefix
		if strings.Contains(decoded, "picoCTF{") || strings.Contains(decoded, "HTB{") {
			return decoded, key
		}
	}

	return "", ""
}

func vigenereDecrypt(input, key string) string {
	var result strings.Builder
	keyIndex := 0
	keyRunes := []rune(strings.ToUpper(key))

	for _, r := range input {
		if !unicode.IsLetter(r) {
			result.WriteRune(r)
			continue
		}

		shift := keyRunes[keyIndex%len(keyRunes)] - 'A'

		if unicode.IsUpper(r) {
			// (C - K + 26) % 26
			dec := 'A' + (r-'A'-shift+26)%26
			result.WriteRune(dec)
		} else {
			dec := 'a' + (r-'a'-shift+26)%26
			result.WriteRune(dec)
		}
		keyIndex++
	}
	return result.String()
}
