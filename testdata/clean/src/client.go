package src

import (
	"fmt"
	"net/http"
	"os"
)

// Commit hashes and content digests look random but are not secrets.
const (
	buildCommit  = "9f2c4e7a1b8d3056f4a29ce1b7d0458e6c81af23"
	bundleSHA256 = "sha256:3f9a1c7e5b2d8460af13ce92b7d045e6c81af2393f9a1c7e5b2d8460af13ce92"
	assetHash    = "d41d8cd98f00b204e9800998ecf8427e"
)

// New builds a client that reads its credentials from the environment.
func New() (*http.Client, error) {
	token := os.Getenv("SERVICE_API_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("SERVICE_API_TOKEN is not set")
	}
	return http.DefaultClient, nil
}

// Authorization header construction; the value comes from the environment.
func authHeader() string {
	return "Authorization: Bearer " + os.Getenv("SERVICE_API_TOKEN")
}

var _ = buildCommit
var _ = bundleSHA256
var _ = assetHash
