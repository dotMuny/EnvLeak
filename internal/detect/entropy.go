package detect

import "math"

// EntropyConfig tunes the entropy engine.
//
// Thresholds were calibrated against testdata/corpus: see docs/decisions.md
// for the sweep. Base64 alphabets carry ~6 bits per symbol, so real random
// material lands around 5.0-5.5 and prose/identifiers below 4.0; hex carries
// 4 bits per symbol and random material sits near 3.9, so the bar is lower.
type EntropyConfig struct {
	Base64Threshold float64
	HexThreshold    float64
	MinLength       int
	// Contextual restricts the standalone generic-high-entropy engine to lines
	// that also mention a secret-ish word. Without it the engine fires on
	// every git hash, UUID and minified bundle in the repository.
	Contextual bool
}

// DefaultEntropyConfig is the calibrated default.
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{
		Base64Threshold: 4.5,
		HexThreshold:    3.0,
		MinLength:       20,
		Contextual:      true,
	}
}

// Shannon returns the Shannon entropy of s in bits per symbol.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	n := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		n++
	}
	entropy := 0.0
	inv := 1.0 / float64(n)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) * inv
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Alphabet classifies the character set a candidate secret is drawn from.
type Alphabet int

// Recognised alphabets.
const (
	AlphabetOther Alphabet = iota
	AlphabetHex
	AlphabetBase64
)

// String implements fmt.Stringer.
func (a Alphabet) String() string {
	switch a {
	case AlphabetHex:
		return "hex"
	case AlphabetBase64:
		return "base64"
	default:
		return "other"
	}
}

// Classify reports which alphabet s is drawn from. Hex is checked first
// because every hex string is also a valid base64 string, and hex material
// carries less entropy per character.
func Classify(s string) Alphabet {
	if s == "" {
		return AlphabetOther
	}
	hex := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		case c >= 'g' && c <= 'z', c >= 'G' && c <= 'Z':
			hex = false
		case c == '+', c == '/', c == '=', c == '-', c == '_':
			hex = false
		default:
			return AlphabetOther
		}
	}
	if hex {
		return AlphabetHex
	}
	return AlphabetBase64
}

// Threshold returns the configured bar for an alphabet, and whether the
// alphabet is one the engine scores at all.
func (c EntropyConfig) Threshold(a Alphabet) (float64, bool) {
	switch a {
	case AlphabetHex:
		return c.HexThreshold, true
	case AlphabetBase64:
		return c.Base64Threshold, true
	default:
		return 0, false
	}
}

// Score returns the entropy of s and whether it clears the bar for its
// alphabet. Strings shorter than MinLength never clear it: Shannon entropy on
// a short string is dominated by sampling noise ("ab12cd34" scores 3.0 on
// eight characters, which means nothing).
func (c EntropyConfig) Score(s string) (float64, bool) {
	if len(s) < c.MinLength {
		return Shannon(s), false
	}
	e := Shannon(s)
	threshold, scored := c.Threshold(Classify(s))
	if !scored {
		return e, false
	}
	return e, e >= threshold
}

// isCandidateByte reports whether b can appear inside a base64/hex candidate.
func isCandidateByte(b byte) bool {
	switch {
	case b >= '0' && b <= '9', b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return true
	case b == '+', b == '/', b == '=', b == '-', b == '_':
		return true
	}
	return false
}

// candidate is a maximal run of secret-shaped characters inside a line.
type candidate struct {
	value string
	start int
	end   int
}

// candidates splits a line into maximal runs of base64/hex-alphabet bytes of
// at least minLen characters.
func candidates(line string, minLen int) []candidate {
	var out []candidate
	start := -1
	for i := 0; i <= len(line); i++ {
		if i < len(line) && isCandidateByte(line[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen {
				out = append(out, candidate{value: line[start:i], start: start, end: i})
			}
			start = -1
		}
	}
	return out
}
