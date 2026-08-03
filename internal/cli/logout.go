package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/elastic-infra/aws-login-vault/internal/keychain"
)

func newLogoutCmd(sf *storeFlags) *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove a cached session from the Keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogout(sf, profile)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", defaultProfile, "profile name")
	return cmd
}

func runLogout(sf *storeFlags, profile string) error {
	store, err := openStore(sf)
	if err != nil {
		return err
	}

	assumedRemoved, err := store.DeleteAssumedForProfile(profile)
	if err != nil {
		return fmt.Errorf("purge assumed cache: %w", err)
	}

	if err := store.Delete(profile); err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			if assumedRemoved > 0 {
				fmt.Fprintf(os.Stderr, "Removed %d assumed-role entries for profile %q (no login session)\n", assumedRemoved, profile)
			} else {
				fmt.Fprintf(os.Stderr, "No session for profile %q\n", profile)
			}
			return nil
		}
		return err
	}
	if assumedRemoved > 0 {
		fmt.Fprintf(os.Stderr, "Removed profile %q (+ %d assumed-role entries) from Keychain\n", profile, assumedRemoved)
	} else {
		fmt.Fprintf(os.Stderr, "Removed profile %q from Keychain\n", profile)
	}
	return nil
}
