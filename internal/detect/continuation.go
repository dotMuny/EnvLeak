package detect

import (
	"fmt"
	"strings"
)

// A Continuation inspects the line following a match and decides whether the
// match is real.
//
// It exists because of one specific and very common false positive: a PEM
// banner quoted in prose. "-----BEGIN RSA PRIVATE KEY-----" in a README, in a
// shell comment, or in an `openssl genrsa` example is documentation. The same
// banner with base64 key material on the next line is a leaked key. A
// line-at-a-time scanner cannot tell them apart without looking one line
// ahead, so it looks one line ahead.
//
// A match whose rule declares a continuation and which reaches end-of-file
// with no following line is dropped: a banner with nothing after it is not a
// key.
type Continuation func(nextLine string) bool

var continuations = map[string]Continuation{
	"pem-body": pemBodyFollows,
}

// HasContinuation reports whether name is a registered continuation check.
func HasContinuation(name string) bool {
	_, ok := continuations[name]
	return ok
}

// ContinuationNames lists the registered checks, for docs and tests.
func ContinuationNames() []string {
	out := make([]string, 0, len(continuations))
	for k := range continuations {
		out = append(out, k)
	}
	return out
}

// pemBodyFollows reports whether a line looks like the first line of PEM key
// material: a long run of base64, or one of the RFC 1421 headers an encrypted
// PEM block carries before its body.
func pemBodyFollows(next string) bool {
	s := strings.TrimSpace(next)
	if s == "" {
		return false
	}
	// Encrypted PEM blocks start with headers, not with the body.
	for _, header := range []string{"Proc-Type:", "DEK-Info:", "Comment:", "Version:"} {
		if strings.HasPrefix(s, header) {
			return true
		}
	}
	// PEM wraps at 64 characters, so anything real is comfortably long. The
	// bar is 32 to tolerate a short final line and indented fixtures.
	if len(s) < 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=':
		default:
			return false
		}
	}
	return true
}

// pending is a finding held back until its continuation can be checked.
type pending struct {
	finding      Finding
	continuation Continuation
	name         string
}

// resolvePending decides the fate of findings deferred from the previous line.
func resolvePending(out []Finding, held []pending, nextLine string) ([]Finding, []pending) {
	for _, p := range held {
		if p.continuation(nextLine) {
			out = append(out, p.finding)
		}
	}
	return out, held[:0]
}

func continuationFor(name string) (Continuation, error) {
	c, ok := continuations[name]
	if !ok {
		return nil, fmt.Errorf("unknown continuation %q", name)
	}
	return c, nil
}
