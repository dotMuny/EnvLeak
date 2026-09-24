package detect

import (
	"regexp"
	"strings"
)

// placeholderLiterals are values that ship in documentation and SDK samples.
// Matching is case-insensitive and substring-based.
var placeholderLiterals = []string{
	"akiaiosfodnn7example",
	"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
	"example",
	"changeme",
	"change_me",
	"change-me",
	"change-this",
	"change_this",
	"please-change",
	"placeholder",
	"redacted",
	"dummy",
	"notreal",
	"not-a-real",
	"yourtoken",
	"your-token",
	"your_token",
	"your-api-key",
	"your_api_key",
	"yourapikey",
	"your-secret",
	"your_secret",
	"my-secret",
	"mysecrethere",
	"insert-your",
	"_here",
	"-here",
	"replace-me",
	"replaceme",
	"todo",
	"fixme",
	"xxxxxxxx",
	"aaaaaaaaaaaa",
	"1234567890ab",
	"abcdefghijkl",
	"deadbeefdeadbeef",
	"lorem",
	"foobar",
	"sample",
	"test-token",
	"testtoken",
	"faketoken",
	"fake-token",
	"secretsecret",
	"password123",
	"hunter2",
	"s3cr3t",
}

// weakSampleValues are matched against the whole captured value, not as a
// substring. "password" as a password is a documentation default; a real
// secret that happens to contain the substring "password" is not, which is
// why these get an exact comparison and the list above gets Contains.
var weakSampleValues = map[string]bool{
	"password": true, "passwd": true, "pass": true, "secret": true,
	"guest": true, "admin": true, "root": true, "user": true,
	"letmein": true, "changeit": true, "123456": true, "12345678": true,
	"qwerty": true, "abc123": true, "test": true, "token": true,
	"apikey": true, "api_key": true, "none": true, "null": true,
	"undefined": true, "true": true, "false": true,
}

// placeholderPatterns catch templating and interpolation syntax: the value is
// not a secret, it is the name of one.
var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`),             // $TOKEN
	regexp.MustCompile(`\$\{[^}]*\}`),                            // ${TOKEN}, ${{ secrets.X }}
	regexp.MustCompile(`\{\{[^}]*\}\}`),                          // {{ .Secret }}, {{ token }}
	regexp.MustCompile(`^<[^>]*>$`),                              // <TOKEN>
	regexp.MustCompile(`^\[[^\]]*\]$`),                           // [TOKEN]
	regexp.MustCompile(`^%[A-Za-z_][A-Za-z0-9_]*%$`),             // %TOKEN%
	regexp.MustCompile(`(?i)^(?:os\.)?(?:environ|getenv|env)\b`), // os.environ["X"]
	regexp.MustCompile(`(?i)\bprocess\.env\b`),                   // process.env.X
	regexp.MustCompile(`(?i)^secrets?\.[A-Za-z0-9_.]+$`),         // secrets.TOKEN
	// Shell and templating interpolation. These are anchored at the start
	// rather than requiring a closing delimiter, because the rule regexes
	// capture up to the first space and so routinely truncate a
	// substitution mid-expression: TOKEN="$(secure_random 32)" is captured
	// as `$(secure_random`.
	regexp.MustCompile(`^\$[({A-Za-z_]`),                     // $(cat f), ${VAR}, $VAR
	regexp.MustCompile("^`"),                                 // `openssl rand -hex 32`
	regexp.MustCompile(`^[Xx]+$`),                            // xxxxxxxxxx
	regexp.MustCompile(`^0+$`),                               // 000000000
	regexp.MustCompile(`(?i)^(?:enter|insert|add|put)[-_ ]`), // enter-your-key
	regexp.MustCompile(`(?i)\b(?:example|sample|dummy|fake)\.(?:com|org|net)\b`),
	// "your-key", "your_api_token", "YOUR KEY HERE" — the documentation
	// convention for "put a real value here".
	regexp.MustCompile(`(?i)your[-_ ](?:key|token|secret|api|auth|password|pass|value|account|org|domain|id|name|here)`),
	// An all-lowercase identifier made of words: "discovery-token",
	// "serviceaccount-token-controller", "auth.session.key". Secrets are not
	// spelled in English. Segments must be purely alphabetic, so a real
	// lowercase credential such as Mailgun's key-<32 hex> is untouched.
	regexp.MustCompile(`^[a-z]+(?:[-_.][a-z]+)+$`),
	// An environment variable NAME being assigned, not its value:
	//     API_KEY_ENV = "SERVICE_API_TOKEN"
	// Real credentials are not screaming snake case.
	regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`),
	// A reference to a variable in a configuration language, not a literal:
	// Terraform's var.db_password, Ansible's vars.token, JS config.apiKey.
	// The roots are listed explicitly rather than matching any dotted
	// identifier, so a JWT (whose segments are long base64) cannot match.
	regexp.MustCompile(`^(?:var|local|module|data|self|this|cls|config|conf|settings|options|opts|props|params|process|os|env|environ|secrets|vars|state)\.[A-Za-z_][A-Za-z0-9_.\[\]"'\-]*$`),
}

// IsPlaceholder reports whether a captured value is an obvious example,
// template variable or filler rather than a live secret.
//
// This is the single highest-leverage false-positive filter in envleak: the
// overwhelming majority of regex hits in a real repository are README samples
// and CI templates.
func IsPlaceholder(secret string) bool {
	s := strings.TrimSpace(secret)
	if s == "" {
		return true
	}
	lower := strings.ToLower(s)
	if weakSampleValues[lower] {
		return true
	}
	for _, lit := range placeholderLiterals {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	for _, re := range placeholderPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	// A single character repeated is padding, never a secret. So is a value
	// containing a long run of one character: "sk_test_0000000000000000000".
	if len(s) >= 8 && distinctChars(s) == 1 {
		return true
	}
	if hasRun(s, 8) {
		return true
	}
	// A value made of fewer than five distinct characters is padding, not a
	// secret: "abababab...", "0101...", "----".
	if len(s) >= 12 && distinctChars(s) < 5 {
		return true
	}
	return false
}

// hasRun reports whether s contains n or more consecutive identical bytes.
func hasRun(s string, n int) bool {
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] != s[i-1] {
			run = 1
			continue
		}
		run++
		if run >= n {
			return true
		}
	}
	return false
}

func distinctChars(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}
