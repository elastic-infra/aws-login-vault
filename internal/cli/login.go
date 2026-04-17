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
	loginflow "github.com/hkobayash/aws-login-vault/internal/login"
)

const loginLockTimeout = 30 * time.Second

func newLoginCmd() *cobra.Command {
	var (
		profile string
		region  string
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in via the browser and cache credentials in macOS Keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd.Context(), profile, region, force)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", defaultProfile, "profile name (used as keychain entry key)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region (required unless resolvable from env or config)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing session without prompting")
	return cmd
}

func runLogin(ctx context.Context, profile, regionFlag string, force bool) error {
	region, err := awsconfig.ResolveRegion(ctx, profile, regionFlag)
	if err != nil {
		return err
	}

	store, err := keychain.Open()
	if err != nil {
		return err
	}

	pl, err := lock.AcquireProfile(profile, loginLockTimeout)
	if err != nil {
		return fmt.Errorf("could not lock profile %q: %w", profile, err)
	}
	defer pl.Release()

	if existing, err := store.Load(profile); err == nil {
		if !force {
			ok, err := confirmOverwrite(profile, existing)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("aborted")
			}
		}
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return err
	}

	cfg, err := awsconfig.NewAWSConfig(ctx, region)
	if err != nil {
		return fmt.Errorf("build aws config: %w", err)
	}

	result, err := loginflow.SameDeviceLogin(ctx, cfg)
	if err != nil {
		return err
	}

	sess := &keychain.Session{
		SessionARN:      result.SessionARN,
		AccessKeyID:     result.AccessKeyID,
		SecretAccessKey: result.SecretAccessKey,
		SessionToken:    result.SessionToken,
		Expiration:      result.Expiration,
		RefreshToken:    result.RefreshToken,
		DPoPKeyPEM:      result.DPoPKeyPEM,
		Region:          result.Region,
		ClientID:        loginflow.SameDeviceClientID,
	}
	if err := store.Save(profile, sess); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Logged in as %s\n", sess.SessionARN)
	fmt.Fprintf(os.Stderr, "Saved profile %q to macOS Keychain (expires in %s)\n",
		profile, time.Until(sess.Expiration).Round(time.Second))
	return nil
}

func confirmOverwrite(profile string, existing *keychain.Session) (bool, error) {
	fmt.Fprintf(os.Stderr,
		"Profile %q already has a session for %s (expires %s).\nOverwrite? [y/N]: ",
		profile, existing.SessionARN, existing.Expiration.Format(time.RFC3339))

	if !isTerminal(os.Stdin) {
		return false, errors.New("non-interactive; pass --force to overwrite")
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes", nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
