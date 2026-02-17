package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// RSAParams holds the extracted RSA variables
type RSAParams struct {
	N *big.Int
	E *big.Int
	C *big.Int
}

// ParseRSA extracts N, e, c from input string (Decimal or Hex)
func ParseRSA(input string) *RSAParams {
	params := &RSAParams{}

	// Regex to find numbers assigned to n, e, c (case insensitive)
	// Supports: "n = 123", "Modulus: 0xabc", "c=..."

	nPattern := regexp.MustCompile(`(?i)(?:n|modulus)\s*[:=]\s*(?:0x)?([0-9a-f]+)`)
	ePattern := regexp.MustCompile(`(?i)(?:e|exponent)\s*[:=]\s*(?:0x)?([0-9a-f]+)`)
	cPattern := regexp.MustCompile(`(?i)(?:c|ciphertext)\s*[:=]\s*(?:0x)?([0-9a-f]+)`)

	extract := func(pattern *regexp.Regexp, input string) *big.Int {
		match := pattern.FindStringSubmatch(input)
		if len(match) > 1 {
			val := new(big.Int)
			rawStr := match[0]
			parts := strings.Split(rawStr, "=")
			if len(parts) < 2 {
				parts = strings.Split(rawStr, ":")
			}
			if len(parts) >= 2 {
				numStr := strings.TrimSpace(parts[1])
				// SetString(s, 0) detects 0x automatically.
				// Our regex might have stripped 0x in capture group 1, but we use numStr from split.
				// If numStr has 0x, it works. If not, it assumes decimal.
				if _, ok := val.SetString(numStr, 0); ok {
					return val
				}
			}
		}
		return nil
	}

	params.N = extract(nPattern, input)
	params.E = extract(ePattern, input)
	params.C = extract(cPattern, input)

	return params
}

// SolveResult from main package (assumed shared or we redefine if needed, but since it's same package main, it's fine)

// SolveRSA attempts to solve the parameters
func SolveRSA(params *RSAParams, online bool) *SolveResult {
	if params.N == nil || params.E == nil || params.C == nil {
		return &SolveResult{Success: false}
	}

	fmt.Printf("%s[+] RSA Detected:%s\n", ColorBlue, ColorReset)
	fmt.Printf("    N: %d bits\n", params.N.BitLen())
	fmt.Printf("    e: %s\n", params.E.String())

	// Attack 1: Small Exponent Attack (m^e < N)
	if params.E.Cmp(big.NewInt(100000)) < 0 { // Check if e is reasonably small
		m := iroot(params.C, params.E)

		// Check m and m+1 to handle potential off-by-one or floor issues in iroot
		candidates := []*big.Int{m, new(big.Int).Add(m, big.NewInt(1))}

		for _, cand := range candidates {
			check := new(big.Int).Exp(cand, params.E, nil)
			if check.Cmp(params.C) == 0 {
				msg := bigIntToString(cand)
				return &SolveResult{
					Success:     true,
					Algorithm:   fmt.Sprintf("RSA Small Exponent (e=%s)", params.E),
					DecodedData: msg,
				}
			}
		}
	}

	// Attack 2: FactorDB (Online)
	if online {
		p, q := queryFactorDB(params.N)
		if p != nil && q != nil {
			fmt.Printf("    %s[+] Attack: FactorDB Lookup (Success)%s\n", ColorGreen, ColorReset)
			one := big.NewInt(1)
			pMinus1 := new(big.Int).Sub(p, one)
			qMinus1 := new(big.Int).Sub(q, one)
			phi := new(big.Int).Mul(pMinus1, qMinus1)

			d := new(big.Int).ModInverse(params.E, phi)
			if d == nil {
				return &SolveResult{Success: false} // gcd(e, phi) != 1
			}

			// m = c^d mod N
			m := new(big.Int).Exp(params.C, d, params.N)
			msg := bigIntToString(m)

			return &SolveResult{
				Success:     true,
				Algorithm:   "RSA FactorDB (Weak Key)",
				DecodedData: msg,
			}
		} else {
			fmt.Printf("    [!] FactorDB: N not factored.\n")
		}
	}

	return &SolveResult{Success: false}
}

// Helper: Integer K-th root using binary search
func iroot(base *big.Int, root *big.Int) *big.Int {
	if root.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int).Set(base)
	}

	low := big.NewInt(0)
	high := new(big.Int).Set(base)
	one := big.NewInt(1)
	ans := big.NewInt(0)

	for low.Cmp(high) <= 0 {
		mid := new(big.Int).Add(low, high)
		mid.Rsh(mid, 1) // mid / 2

		pow := new(big.Int).Exp(mid, root, nil)

		cmp := pow.Cmp(base)
		if cmp == 0 {
			return mid
		} else if cmp < 0 {
			ans.Set(mid)
			low.Add(mid, one)
		} else {
			high.Sub(mid, one)
		}
	}
	return ans
}

func bigIntToString(i *big.Int) string {
	return string(i.Bytes())
}

// FactorDB API Logic
type FactorDBResponse struct {
	ID      string          `json:"id"`
	Status  string          `json:"status"`
	Factors [][]interface{} `json:"factors"`
}

func queryFactorDB(N *big.Int) (*big.Int, *big.Int) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://factordb.com/api?query=%s", N.String())

	resp, err := client.Get(url)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	var result FactorDBResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil
	}

	if result.Status == "FF" || result.Status == "CF" {
		if len(result.Factors) >= 2 {
			getFactor := func(f interface{}) string {
				switch v := f.(type) {
				case string:
					return v
				case float64:
					return fmt.Sprintf("%.0f", v)
				default:
					return ""
				}
			}

			pStr := getFactor(result.Factors[0][0])
			qStr := getFactor(result.Factors[1][0])

			p := new(big.Int)
			q := new(big.Int)
			p.SetString(pStr, 0)
			q.SetString(qStr, 0)

			if p.Sign() > 0 && q.Sign() > 0 {
				return p, q
			}
		}
		if len(result.Factors) == 1 {
			pow, ok := result.Factors[0][1].(float64)
			if ok && pow == 2 {
				getFactor := func(f interface{}) string {
					switch v := f.(type) {
					case string:
						return v
					case float64:
						return fmt.Sprintf("%.0f", v)
					default:
						return ""
					}
				}
				pStr := getFactor(result.Factors[0][0])
				p := new(big.Int)
				p.SetString(pStr, 0)
				return p, p
			}
		}
	}

	return nil, nil
}
