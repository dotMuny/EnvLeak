package auth

import "testing"

// Fixture values. None of these are real credentials.
const (
	fakeToken   = "test-token-0000000000000000"
	fakeAPIKey  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fakeBearer  = "Bearer dummy-token-for-tests-only"
	fixtureHash = "0000000000000000000000000000000000000000"
)

func TestAuth(t *testing.T) {
	if fakeToken == "" || fakeAPIKey == "" || fakeBearer == "" || fixtureHash == "" {
		t.Fatal("fixtures missing")
	}
}
