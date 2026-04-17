package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hkobayash/aws-login-vault/internal/keychain"
)

func newLogoutCmd() *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove a cached session from the Keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogout(profile)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", defaultProfile, "profile name")
	return cmd
}

func runLogout(profile string) error {
	store, err := keychain.Open()
	if err != nil {
		return err
	}
	if err := store.Delete(profile); err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "No session for profile %q\n", profile)
			return nil
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "Removed profile %q from Keychain\n", profile)
	return nil
}
