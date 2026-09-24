package detect

import (
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"strings"
)

// A Validator inspects a candidate secret's internal structure — a checksum, a
// decodable payload — and reports whether it is self-consistent.
//
// Validators are advisory and fail open: a value that does not validate is
// still reported, one confidence level lower, never dropped. A validator that
// silently swallowed findings would trade a false-positive problem for a much
// worse false-negative one, and provider token formats change without notice.
// See docs/decisions.md.
type Validator func(secret string) bool

var validators = map[string]Validator{
	"github-crc32":         validateGitHubCRC32,
	"github-pat-structure": validateGitHubFineGrained,
	"jwt":                  validateJWT,
}

// HasValidator reports whether name is a registered validator.
func HasValidator(name string) bool {
	_, ok := validators[name]
	return ok
}

// ValidatorNames lists the registered validators, for docs and tests.
func ValidatorNames() []string {
	out := make([]string, 0, len(validators))
	for k := range validators {
		out = append(out, k)
	}
	return out
}

// base62Alphabet is the alphabet GitHub uses for the trailing checksum of its
// prefixed tokens.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// base62Encode renders n in base62, left-padded with zeroes to width.
func base62Encode(n uint32, width int) string {
	if n == 0 {
		return strings.Repeat("0", width)
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append(buf, base62Alphabet[n%62])
		n /= 62
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	if len(buf) < width {
		return strings.Repeat("0", width-len(buf)) + string(buf)
	}
	return string(buf)
}

// GitHubChecksum returns the 6-character base62 CRC32 checksum GitHub appends
// to a prefixed token payload. It is exported so tests can build tokens that
// are valid by construction.
func GitHubChecksum(payload string) string {
	return base62Encode(crc32.ChecksumIEEE([]byte(payload)), 6)
}

// validateGitHubCRC32 checks the checksum of a prefixed GitHub token
// (ghp_/gho_/ghu_/ghs_/ghr_). The body is 36 base62 characters: 30 of random
// payload followed by a 6-character base62 CRC32 of that payload.
func validateGitHubCRC32(secret string) bool {
	i := strings.IndexByte(secret, '_')
	if i < 0 || i+1 >= len(secret) {
		return false
	}
	body := secret[i+1:]
	if len(body) != 36 {
		return false
	}
	payload, checksum := body[:30], body[30:]
	return GitHubChecksum(payload) == checksum
}

// validateGitHubFineGrained checks the structure of a fine-grained PAT.
// GitHub does not document a checksum for this format, so we verify the shape:
// github_pat_ + 22 base62 + '_' + 59 base62.
func validateGitHubFineGrained(secret string) bool {
	const prefix = "github_pat_"
	if !strings.HasPrefix(secret, prefix) {
		return false
	}
	rest := secret[len(prefix):]
	sep := strings.IndexByte(rest, '_')
	if sep != 22 {
		return false
	}
	return len(rest[sep+1:]) == 59 && isBase62(rest[:sep]) && isBase62(rest[sep+1:])
}

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return len(s) > 0
}

// validateJWT decodes the header of a three-segment token and requires it to
// be a JSON object carrying an "alg" claim. This rejects the very common
// false positive of an unrelated base64 blob that happens to start with "eyJ".
func validateJWT(secret string) bool {
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return false
	}
	alg, ok := header["alg"].(string)
	return ok && alg != ""
}
