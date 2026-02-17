package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// SolveResult contains the result of a local decryption/decoding attempt
type SolveResult struct {
	Success     bool
	Algorithm   string
	DecodedData string
}

// Solver encapsulates local solving logic
type Solver struct{}

// NewSolver creates a new local solver instance
func NewSolver() *Solver {
	return &Solver{}
}

// TryDecode attempts all standard encodings
func (s *Solver) TryDecode(input string) *SolveResult {
	// Try Base64
	if data, err := base64.StdEncoding.DecodeString(input); err == nil {
		// Heuristic: if it decodes to only printable chars, it's likely correct
		if isPrintable(data) {
			return &SolveResult{Success: true, Algorithm: "Base64", DecodedData: string(data)}
		}
	}

	// Try Hex
	if data, err := hex.DecodeString(input); err == nil {
		if isPrintable(data) {
			return &SolveResult{Success: true, Algorithm: "Hex", DecodedData: string(data)}
		}
	}

	// Try URL
	if data, err := url.QueryUnescape(input); err == nil && data != input {
		return &SolveResult{Success: true, Algorithm: "URL Encoding", DecodedData: data}
	}

	// Try Base32
	if data, err := base32.StdEncoding.DecodeString(input); err == nil {
		if isPrintable(data) {
			return &SolveResult{Success: true, Algorithm: "Base32", DecodedData: string(data)}
		}
	}

	// Try Rot13
	rot13 := s.Rot13(input)
	// Simple check: does it look like a flag or English?
	// The prompt implies "Auto-solve" Rot13. We'll just return it if it contains "pico" or similar,
	// or we can just return it as a candidate if requested.
	// For "Auto-solve", we might need a heuristic.
	if strings.Contains(strings.ToLower(rot13.DecodedData), "pico") {
		return rot13
	}

	// Try Caesar Brute Force (looking for flag format)
	caesar := s.BruteForceCaesar(input)
	if caesar.Success {
		return caesar
	}

	return &SolveResult{Success: false}
}

// Rot13 implementation
func (s *Solver) Rot13(input string) *SolveResult {
	var result strings.Builder
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			result.WriteRune('A' + (r-'A'+13)%26)
		default:
			result.WriteRune(r)
		}
	}
	return &SolveResult{Success: true, Algorithm: "Rot13", DecodedData: result.String()}
}

// BruteForceCaesar shifts 1-25 looking for "picoCTF{"
func (s *Solver) BruteForceCaesar(input string) *SolveResult {
	target := "picoctf" // Case insensitive check

	for shift := 1; shift < 26; shift++ {
		var result strings.Builder
		for _, r := range input {
			switch {
			case r >= 'a' && r <= 'z':
				// Python: chr((ord(char) - 97 + shift) % 26 + 97)
				// Go: 'a' + (r-'a'+rune(shift))%26
				result.WriteRune('a' + (r-'a'+rune(shift))%26)
			case r >= 'A' && r <= 'Z':
				result.WriteRune('A' + (r-'A'+rune(shift))%26)
			default:
				result.WriteRune(r)
			}
		}
		candidate := result.String()
		if strings.Contains(strings.ToLower(candidate), target) {
			return &SolveResult{
				Success:     true,
				Algorithm:   fmt.Sprintf("Caesar Cipher (Shift %d)", shift),
				DecodedData: candidate,
			}
		}
	}
	return &SolveResult{Success: false}
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		// Allow some standard whitespace
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
		if b > 126 {
			return false
		}
	}
	return true
}
