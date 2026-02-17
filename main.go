package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI Colors
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

func main() {
	textInput := flag.String("t", "", "Text input to analyze")
	fileInput := flag.String("f", "", "File input to analyze")
	onlineMode := flag.Bool("online", false, "Enable active online lookups")
	flag.Parse()

	var inputData []byte
	var err error

	// 1. Read Input
	if *textInput != "" {
		inputData = []byte(*textInput)
	} else if *fileInput != "" {
		inputData, err = os.ReadFile(*fileInput)
		if err != nil {
			fmt.Printf("%sError reading file: %v%s\n", ColorRed, err, ColorReset)
			os.Exit(1)
		}
	} else {
		// Check for stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			inputData, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Printf("%sError reading stdin: %v%s\n", ColorRed, err, ColorReset)
				os.Exit(1)
			}
		} else {
			fmt.Println("Usage: ./cipher-sleuth -t <text> | -f <file> or pipe input")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	// Trim whitespace for text processing if it's likely text (no null bytes)
	if !bytes.Contains(inputData, []byte{0}) {
		inputData = bytes.TrimSpace(inputData)
	}

	// Orchestrator Logic
	orchestrate(inputData, *onlineMode, 0)
}

func orchestrate(data []byte, online bool, depth int) {
	if depth > 5 {
		fmt.Printf("%s[!] Max recursion depth reached. Stopping.%s\n", ColorYellow, ColorReset)
		return
	}

	fmt.Printf("\n%s[+] Analysis (Layer %d):%s\n", ColorBlue, depth, ColorReset)

	// 2. Identification
	identifiedType := "Unknown"

	// Check Magic Bytes
	for name, signature := range Config.MagicBytes {
		if len(data) >= len(signature) && bytes.Equal(data[:len(signature)], signature) {
			identifiedType = fmt.Sprintf("File (%s)", name)
			break
		}
	}

	// Check Hashes (if text)
	dataStr := string(data)
	if identifiedType == "Unknown" {
		for name, regex := range Config.HashPatterns {
			if regex.MatchString(dataStr) {
				identifiedType = fmt.Sprintf("Hash (%s)", name)
				break
			}
		}
	}

	// Check Encodings (roughly)
	if identifiedType == "Unknown" {
		for name, regex := range EncodingChecks {
			if regex.MatchString(dataStr) {
				identifiedType = fmt.Sprintf("Encoded Text (%s?)", name)
				break // Just a guess, continue analysis
			}
		}
	}

	// NEW: Check for RSA Parameters (N, e, c pattern)
	rsaParams := ParseRSA(dataStr)
	isRSA := rsaParams.N != nil && rsaParams.E != nil && rsaParams.C != nil
	if isRSA {
		identifiedType = "RSA Challenge Data"
	}

	fmt.Printf("    Type: %s%s%s\n", ColorCyan, identifiedType, ColorReset)

	// 3. Statistics
	entropy := CalculateShannonEntropy(data)
	ioc := CalculateIoC(data)

	entropyDesc := "Low"
	if entropy > 7.5 {
		entropyDesc = "High (Encrypted/Compressed)"
	} else if entropy > 5.0 {
		entropyDesc = "Medium (Random Text/Code)"
	} else {
		entropyDesc = "Low (Standard Text)"
	}

	fmt.Printf("    Entropy: %.2f (%s)\n", entropy, entropyDesc)
	fmt.Printf("    IoC: %.2f (English ~1.73, Random ~1.0)\n", ioc)

	// NEW: RSA Solver Hook
	if isRSA {
		fmt.Printf("%s[+] RSA Solver:%s\n", ColorBlue, ColorReset)
		rsaResult := SolveRSA(rsaParams, online)
		if rsaResult.Success {
			fmt.Printf("    %sSuccess! Algorithm: %s%s\n", ColorGreen, rsaResult.Algorithm, ColorReset)
			fmt.Printf("    Decoded: %s\n", rsaResult.DecodedData)
			return // RSA solved, usually final flag
		} else {
			fmt.Printf("    %sFailed to solve RSA (Small E or FactorDB failed).%s\n", ColorYellow, ColorReset)
		}
	}

	// 4. Local Solver
	if depth == 0 || strings.Contains(identifiedType, "Encoded") || entropy < 7.5 {
		fmt.Printf("%s[+] Local Solver:%s\n", ColorBlue, ColorReset)
		solver := NewSolver()
		result := solver.TryDecode(dataStr)

		if result.Success {
			fmt.Printf("    %sSuccess! Algorithm: %s%s\n", ColorGreen, result.Algorithm, ColorReset)
			fmt.Printf("    Decoded: %s\n", result.DecodedData)

			// Recurse!
			orchestrate([]byte(result.DecodedData), online, depth+1)
			return // Stop current layer processing if successfully decoded to avoid double noise
		} else {
			fmt.Printf("    %sFailed to decode locally.%s\n", ColorYellow, ColorReset)
		}
	}

	// NEW: Poly Solver (XOR & Vigenère)
	if identifiedType == "Unknown" || entropy > 3.0 {
		fmt.Printf("%s[+] Poly Solver:%s\n", ColorBlue, ColorReset)

		// 1. XOR
		xorRes, xorKey, xorScore := SolveSingleByteXOR(data)
		// Threshold for "Success": Score > 70% of length? Or just high confidence?
		// Relative score is hard without length normalization in stats, but let's use a heuristic.
		// If score is high enough or "flag" found (score 1000).
		if xorScore >= 1000.0 {
			fmt.Printf("    %sSuccess! Algorithm: Single Byte XOR (Key: 0x%02X)%s\n", ColorGreen, xorKey, ColorReset)
			fmt.Printf("    Decoded: %s\n", xorRes)
			return
		}

		// 2. Vigenère (Only if text-like)
		if entropy < 6.0 {
			vigRes, vigKey := SolveVigenere(dataStr)
			if vigRes != "" {
				fmt.Printf("    %sSuccess! Algorithm: Vigenère (Key: %s)%s\n", ColorGreen, vigKey, ColorReset)
				fmt.Printf("    Decoded: %s\n", vigRes)
				return
			}
		}

		// If we found a decent XOR candidate but it wasn't a "win", maybe print it?
		// For now, only print wins to avoid noise as requested ("Return... winner").
		fmt.Printf("    %sNo Poly-Alphabetic, XOR, or weak RSA matches found.%s\n", ColorYellow, ColorReset)
	}

	// 5. Online Solver (Fallback)
	fmt.Printf("%s[+] Online Fallback:%s\n", ColorBlue, ColorReset)
	onlineSolver := NewOnlineSolver()

	if online {
		// Attempt Active Lookup if it looks like a hash
		if strings.Contains(identifiedType, "Hash") {
			// Extract hash type name for lookup
			parts := strings.Split(identifiedType, "(")
			if len(parts) > 1 {
				hashType := strings.TrimRight(parts[1], ")")
				success, result := onlineSolver.ActiveLookup(dataStr, hashType)
				if success {
					fmt.Printf("    %sActive Lookup: Success!%s\n", ColorGreen, ColorReset)
					fmt.Printf("    Results: %s\n", result)
					return
				} else {
					fmt.Printf("    %sActive Lookup: Failed or Not Supported.%s\n", ColorRed, ColorReset)
				}
			}
		}
	}

	// Always show passive links
	onlineSolver.GenerateMagicLinks(dataStr)
}
