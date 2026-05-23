package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hkobayash/aws-login-vault/internal/awsconfig"
	"github.com/hkobayash/aws-login-vault/internal/keychain"
	"github.com/hkobayash/aws-login-vault/internal/lock"
)

const loginLockTimeout = 30 * time.Second

func newLoginCmd(sf *storeFlags) *cobra.Command {
	var (
		profile string
		region  string
		force   bool
		remote  bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in via the browser and cache credentials in the secure store",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd.Context(), sf, profile, region, force, remote)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", defaultProfile, "profile name (used as keychain entry key)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (required unless resolvable from env or config)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite even if the new sub differs from the existing session")
	cmd.Flags().BoolVar(&remote, "remote", false,
		"use cross-device flow (display URL and paste verification code instead of opening a local callback)")
	return cmd
}

func runLogin(ctx context.Context, sf *storeFlags, profile, regionFlag string, force, remote bool) error {
	region, err := awsconfig.ResolveRegion(ctx, profile, regionFlag)
	if err != nil {
		return err
	}

	store, err := openStore(sf)
	if err != nil {
		return err
	}

	pl, err := lock.AcquireProfile(ctx, profile, loginLockTimeout)
	if err != nil {
		return fmt.Errorf("could not lock profile %q: %w", profile, err)
	}
	defer func() { _ = pl.Release() }()

	existing, err := store.Load(profile)
	if err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return err
	}

	sess, err := performBrowserLogin(ctx, store, browserLoginOptions{
		profile: profile,
		region:  region,
		prev:    existing,
		force:   force,
		remote:  remote,
	})
	if err != nil {
		if errors.Is(err, ErrSessionARNMismatch) {
			return fmt.Errorf("%w; use --force with --profile %s if this is intentional", err, profile)
		}
		return err
	}

	fmt.Fprintf(os.Stderr, "Logged in as %s\n", sess.SessionARN)
	fmt.Fprintf(os.Stderr, "Saved profile %q to secure store (expires in %s)\n",
		profile, time.Until(sess.Expiration).Round(time.Second))
	return nil
}

// stdinReadVerificationCode prompts the user on stderr and reads a single
// line from stdin. Used by CROSS_DEVICE login; never invoked from the
// credential_process path.
func stdinReadVerificationCode() (string, error) {
	fmt.Fprint(os.Stderr, "Verification code: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
