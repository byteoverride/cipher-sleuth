package main

import (
	"math"
)

// CalculateShannonEntropy returns a float (0-8) representing data entropy
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	frequencies := make(map[byte]float64)
	for _, b := range data {
		frequencies[b]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range frequencies {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// CalculateIndexOfCoincidence measures the probability that two randomly selected
// letters from the text are the same.
// English text ~ 1.73 (normalized for 26 letters usually in crypto, but here we do byte-based)
// Standard IoC for English (A-Z) is ~0.0667, Random is ~0.0385 (1/26)
//
// However, the prompt specifies:
// ~1.73: English text
// ~0.06: Random/Polyalphabetic cipher
//
// The 1.73 value usually comes from the formula IoC * 26 (Normalization factor).
// We will implement standard IoC and then normalize if needed to match prompt expectations.
// Standard Definition: sum(fi * (fi-1)) / (N * (N-1))
func CalculateIoC(data []byte) float64 {
	if len(data) <= 1 {
		return 0
	}

	// Filter for alphabetic characters only to match "English text" IoC context
	// If we do raw bytes, IoC for random byte stream (0-255) is ~1/256 = 0.0039
	// The prompt's values (1.73 vs 0.06) strongly suggest Normalized IoC over A-Z.

	counts := make(map[byte]int)
	totalChars := 0

	for _, b := range data {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			// Normalize to lowercase for counting
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			counts[b]++
			totalChars++
		}
	}

	if totalChars <= 1 {
		return 0.0
	}

	numerator := 0.0
	for _, count := range counts {
		numerator += float64(count) * float64(count-1)
	}

	denominator := float64(totalChars) * float64(totalChars-1)
	rawIoC := numerator / denominator

	// Prompt: "~1.73 English text". This is Normalized IoC (Raw * 26).
	// Raw English IoC is ~0.0667. 0.0667 * 26 = 1.7342.
	// Prompt: "~0.06 Random". This implies Raw * 26? No.
	// Random (uniform) over 26 chars is 1/26 = 0.038. 0.038 * 26 = 1.0.
	//
	// WAIT. Let's re-read carefully:
	// "~1.73: English text." -> Normalized (Kappa-text)
	// "~0.06: Random/Polyalphabetic cipher." -> Wait, 0.06 is close to Raw English (0.067).
	// But 0.06 is also often cited as "Random" in some contexts IF referring to specific normalization or just raw 1/26 (0.038) vs 1/N.
	//
	// Let's assume the prompt *means* specific standard values often found in CTF tools.
	// - English Index of Coincidence is typically cited as ~0.0667.
	// - Random text (uniform) is ~0.0385 (1/26).
	//
	// If the prompt says "1.73 = English", they likely mean the *normalized* value `IoC * 26`.
	// If they say "0.06 = Random", they might be mixing units or referring to the raw value for English?
	// Actually, 0.06 is very low for "Normalized" (expected 1.0 for random).
	//
	// HYPOTHESIS: The prompt might have mixed up values or meant:
	// 1.73 -> Normalized English (Kappa-p)
	// 0.06 -> Raw English IoC (Probability).
	// OR 0.9-1.0 is random normalized.
	//
	// Correct Approach matching typical crypto tools:
	// Calculate Raw IoC.
	// If Raw IoC ~= 0.066 -> English.
	// If Raw IoC ~= 0.038 -> Random.
	//
	// Let's return the "Normalized IoC" (x26) to hit the 1.73 target,
	// and just handle the output display logic in main logic to interpret it.
	// If user wants 0.06 for random, that's surprisingly low for *normalized* (which is ~1.0).
	// Be safe: I will return the Normalized IoC (x26).
	// English: ~1.73. Random: ~1.0.
	// Use comments to explain.

	return rawIoC * 26.0
}
