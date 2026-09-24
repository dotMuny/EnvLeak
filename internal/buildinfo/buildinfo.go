// Package buildinfo carries version metadata injected at link time.
package buildinfo

import "fmt"

// Overridden with -ldflags at build time; see the Makefile.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String renders a one-line human readable version banner.
func String() string {
	return fmt.Sprintf("envleak %s (commit %s, built %s)", Version, Commit, Date)
}
