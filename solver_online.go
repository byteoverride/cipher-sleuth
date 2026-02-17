package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// OnlineSolver handles online operations
type OnlineSolver struct {
	Client *http.Client
}

// NewOnlineSolver creates a new online solver with a 2s timeout
func NewOnlineSolver() *OnlineSolver {
	return &OnlineSolver{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// GenerateMagicLinks prints passive fallback links
func (s *OnlineSolver) GenerateMagicLinks(input string) {
	// CyberChef
	// Magic recipe is often used, or we can just pass input
	// CyberChef URL format: https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=...
	// We need to base64 encode the input for the URL prompt usually, or URL encode
	encodedInput := url.QueryEscape(input)
	fmt.Printf("  - CyberChef (Magic): https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=%s\n", encodedInput)

	// dCode
	// dCode doesn't have a generic "magic" but has specific tools.
	// We can link to the identifier or a common one.
	fmt.Printf("  - dCode (Cipher Identifier): https://www.dcode.fr/cipher-identifier\n")
}

// ActiveLookup attempts to reverse a hash using online APIs
func (s *OnlineSolver) ActiveLookup(hash string, hashType string) (bool, string) {
	// Simple active lookup for MD5/SHA1 using nitrxgen or hashtoolkit
	// Note: these are examples and might not always work or have rate limits.
	// We'll try nitrxgen for MD5 as requested in prompt.

	if hashType == "MD5" || hashType == "NTLM" {
		// NTLM and MD5 have the same format (32 hex chars).
		// We'll try the MD5 lookup service for both.
		return s.lookupNitrxgen(hash)
	}

	// For other hashes, we could add more APIs, but for this task we'll implement MD5 as the primary example
	// or maybe a generic one if available.

	return false, ""
}

func (s *OnlineSolver) lookupNitrxgen(hash string) (bool, string) {
	url := fmt.Sprintf("https://www.nitrxgen.net/md5db/%s", hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, ""
	}

	// Custom User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; CipherSleuth/1.0; +https://github.com/byteoverride/cipher-sleuth)")

	resp, err := s.Client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 0 {
			return true, string(body)
		}
	}
	return false, ""
}
