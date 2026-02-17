package main

import "regexp"

// KnowledgeBase defines our static database of signatures
type KnowledgeBase struct {
	HashPatterns   map[string]*regexp.Regexp
	MagicBytes     map[string][]byte
	AsymmetricKeys map[string]*regexp.Regexp
}

// Config holds the global configuration and knowledge base
var Config = KnowledgeBase{
	HashPatterns: map[string]*regexp.Regexp{
		"MD5":        regexp.MustCompile(`^[a-fA-F0-9]{32}$`),
		"SHA1":       regexp.MustCompile(`^[a-fA-F0-9]{40}$`),
		"SHA256":     regexp.MustCompile(`^[a-fA-F0-9]{64}$`),
		"SHA512":     regexp.MustCompile(`^[a-fA-F0-9]{128}$`),
		"RIPEMD-160": regexp.MustCompile(`^[a-fA-F0-9]{40}$`),
		"NTLM":       regexp.MustCompile(`^[a-fA-F0-9]{32}$`),
		"Bcrypt":     regexp.MustCompile(`^\$2[ayb]\$.{56}$`),
		"Argon2":     regexp.MustCompile(`^\$argon2.*\$.+$`),
	},
	MagicBytes: map[string][]byte{
		"PNG":       {0x89, 0x50, 0x4E, 0x47},
		"JPG":       {0xFF, 0xD8, 0xFF},
		"ZIP":       {0x50, 0x4B, 0x03, 0x04},
		"7z":        {0x37, 0x7A, 0xBC, 0xAF},
		"TAR":       {0x75, 0x73, 0x74, 0x61, 0x72}, // ustar
		"ELF":       {0x7F, 0x45, 0x4C, 0x46},
		"LUKS":      {0x4C, 0x55, 0x4B, 0x53}, // LUKS
		// VeraCrypt doesn't have a fixed header, it's random, so detection is hard via magic bytes alone
		// But we can check for high entropy in main logic.
		"PGP Message": {0x85}, // Rough check, usage depends on context
	},
	AsymmetricKeys: map[string]*regexp.Regexp{
		"RSA Private Key": regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		"RSA Public Key":  regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`),
		"SSH Private Key": regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		"PGP Public Key":  regexp.MustCompile(`-----BEGIN PGP PUBLIC KEY BLOCK-----`),
		"PGP Private Key": regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	},
}

// EncodingChecks for basic string identification
var EncodingChecks = map[string]*regexp.Regexp{
	"Base64": regexp.MustCompile(`^[a-zA-Z0-9+/]*={0,2}$`),
	"Base32": regexp.MustCompile(`^[A-Z2-7]*={0,6}$`),
	"Base58": regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]+$`),
	"Hex":    regexp.MustCompile(`^[a-fA-F0-9]+$`),
	"URL":    regexp.MustCompile(`%[0-9a-fA-F]{2}`),
}
