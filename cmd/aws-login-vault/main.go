package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/elastic-infra/aws-login-vault/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRoot()
	root.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	if err := root.ExecuteContext(ctx); err != nil {
		var ece *cli.ExitCodeError
		if errors.As(err, &ece) {
			os.Exit(ece.Code)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
