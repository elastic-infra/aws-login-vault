package cli

import (
	"os"

	"github.com/spf13/cobra"
)

const (
	defaultProfile = "default"
	envBackend     = "AWS_LOGIN_VAULT_BACKEND"
)

// storeFlags collects root-level persistent flags that affect store selection.
// Subcommands receive a pointer so they can read the resolved values inside
// RunE after cobra has parsed flags.
type storeFlags struct {
	backendRaw string
}

func NewRoot() *cobra.Command {
	sf := &storeFlags{}
	root := &cobra.Command{
		Use:           "aws-login-vault",
		Short:         "Browser-based AWS console login cached in macOS Keychain",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&sf.backendRaw, "backend",
		os.Getenv(envBackend),
		"force a secure store backend: keychain | secret-service | pass | keyctl (default: auto-detect)")
	root.AddCommand(
		newLoginCmd(sf),
		newLogoutCmd(sf),
		newListCmd(sf),
		newExportCmd(sf),
		newShowCmd(sf),
	)
	return root
}
