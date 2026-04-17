package cli

import (
	"github.com/spf13/cobra"
)

const defaultProfile = "default"

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "aws-login-vault",
		Short:         "Browser-based AWS console login cached in macOS Keychain",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newLoginCmd(),
		newLogoutCmd(),
		newListCmd(),
		newExportCmd(),
		newShowCmd(),
	)
	return root
}
