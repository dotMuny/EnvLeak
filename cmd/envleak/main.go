// Command envleak finds leaked secrets in a Git repository's working tree and
// history.
//
// main is deliberately tiny: it wires signals to a context, hands off to
// internal/cli and translates the result into an exit code. It is also the one
// place in the program allowed to call os.Exit.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/dotMuny/EnvLeak/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	streams := cli.StdIO()
	root := cli.NewRootCommand(streams)
	os.Exit(cli.ExecuteContext(ctx, root, streams))
}
