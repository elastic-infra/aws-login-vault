package cli

import (
	"context"
	"encoding/json"
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

const (
	refreshThreshold   = 60 * time.Second
	refreshLockTimeout = 30 * time.Second
)

const (
	formatJSON = "json"
	formatEnv  = "env"
)

// credentialProcessOutput matches the AWS CLI credential_process protocol v1.
type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

func newExportCmd() *cobra.Command {
	var (
		profile string
		format  string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print credentials for a profile (for credential_process or shell use)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(cmd.Context(), profile, format)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", defaultProfile, "profile name")
	cmd.Flags().StringVar(&format, "format", formatJSON, "output format: json | env")
	return cmd
}

func runExport(ctx context.Context, profile, format string) error {
	if format != formatJSON && format != formatEnv {
		return fmt.Errorf("unknown --format %q (expected json or env)", format)
	}

	store, err := keychain.Open()
	if err != nil {
		return err
	}

	sess, err := getOrRefresh(ctx, store, profile)
	if err != nil {
		return err
	}

	return writeCredentials(sess, format)
}

func getOrRefresh(ctx context.Context, store *keychain.Store, profile string) (*keychain.Session, error) {
	sess, err := store.Load(profile)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, fmt.Errorf("profile %q is not logged in; run: aws-login-vault login --profile %s", profile, profile)
		}
		return nil, err
	}

	if time.Until(sess.Expiration) > refreshThreshold {
		return sess, nil
	}

	pl, err := lock.AcquireProfile(profile, refreshLockTimeout)
	if err != nil {
		return nil, fmt.Errorf("lock profile %q: %w", profile, err)
	}
	defer func() { _ = pl.Release() }()

	// Another process may have refreshed while we waited; re-read before acting.
	sess, err = store.Load(profile)
	if err != nil {
		return nil, err
	}
	if time.Until(sess.Expiration) > refreshThreshold {
		return sess, nil
	}

	cfg, err := awsconfig.NewAWSConfig(ctx, sess.Region)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}

	prev := &loginflow.LoginResult{
		RefreshToken: sess.RefreshToken,
		DPoPKeyPEM:   sess.DPoPKeyPEM,
		SessionARN:   sess.SessionARN,
		Region:       sess.Region,
		ClientID:     sess.ClientID,
	}
	refreshed, err := loginflow.Refresh(ctx, cfg, prev)
	if err != nil {
		if loginflow.IsReloginRequired(err) {
			return nil, fmt.Errorf("refresh failed (%w); run: aws-login-vault login --profile %s", err, profile)
		}
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	newSess := sessionFromLoginResult(refreshed)
	if err := store.Save(profile, newSess); err != nil {
		return nil, fmt.Errorf("save refreshed session: %w", err)
	}
	return newSess, nil
}

func writeCredentials(sess *keychain.Session, format string) error {
	switch format {
	case formatJSON:
		return writeJSON(sess)
	case formatEnv:
		return writeEnv(sess)
	}
	return fmt.Errorf("unknown format %q", format)
}

func writeJSON(sess *keychain.Session) error {
	out := credentialProcessOutput{
		Version:         1,
		AccessKeyId:     sess.AccessKeyID,
		SecretAccessKey: sess.SecretAccessKey,
		SessionToken:    sess.SessionToken,
		Expiration:      sess.Expiration.UTC().Format(time.RFC3339),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeEnv(sess *keychain.Session) error {
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", shellQuote(sess.AccessKeyID))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", shellQuote(sess.SecretAccessKey))
	if sess.SessionToken != "" {
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", shellQuote(sess.SessionToken))
	}
	fmt.Printf("export AWS_CREDENTIAL_EXPIRATION=%s\n",
		shellQuote(sess.Expiration.UTC().Format(time.RFC3339)))
	if sess.Region != "" {
		fmt.Printf("export AWS_REGION=%s\n", shellQuote(sess.Region))
		fmt.Printf("export AWS_DEFAULT_REGION=%s\n", shellQuote(sess.Region))
	}
	return nil
}

// shellQuote wraps a value in single quotes, escaping embedded quotes so the
// output is safe to paste into bash/zsh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
