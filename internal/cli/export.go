package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"

	"github.com/hkobayash/aws-login-vault/internal/awsconfig"
	"github.com/hkobayash/aws-login-vault/internal/keychain"
	"github.com/hkobayash/aws-login-vault/internal/lock"
	loginflow "github.com/hkobayash/aws-login-vault/internal/login"
)

const (
	refreshThreshold   = 60 * time.Second
	refreshLockTimeout = 30 * time.Second

	envAutoLogin = "AWS_LOGIN_VAULT_AUTO_LOGIN"

	sourceIdentityAuto = "auto"
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

type exportOptions struct {
	profile         string
	format          string
	roleARN         string
	roleSessionName string
	sourceIdentity  string
	roleDuration    time.Duration
	autoLogin       bool
}

func newExportCmd() *cobra.Command {
	opts := exportOptions{}
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print credentials for a profile (for credential_process or shell use)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", defaultProfile, "profile name")
	cmd.Flags().StringVar(&opts.format, "format", formatJSON, "output format: json | env")
	cmd.Flags().StringVar(&opts.roleARN, "role", "", "role ARN to assume (enables AssumeRole mode)")
	cmd.Flags().StringVar(&opts.roleSessionName, "role-session-name", "", "RoleSessionName override (default: derived from sub)")
	cmd.Flags().StringVar(&opts.sourceIdentity, "source-identity", "", `SourceIdentity for AssumeRole. "auto" derives from sub; any other value is sent literally`)
	cmd.Flags().DurationVar(&opts.roleDuration, "role-duration", 0, "AssumeRole DurationSeconds (default 1h)")
	cmd.Flags().BoolVar(&opts.autoLogin, "auto-login", os.Getenv(envAutoLogin) == "1",
		"run login automatically if the profile is not authenticated (requires a local GUI session)")
	return cmd
}

func runExport(ctx context.Context, opts exportOptions) error {
	if opts.format != formatJSON && opts.format != formatEnv {
		return fmt.Errorf("unknown --format %q (expected json or env)", opts.format)
	}

	store, err := keychain.Open()
	if err != nil {
		return err
	}

	baseSession, err := prepareBaseSession(ctx, store, opts.profile, opts.autoLogin)
	if err != nil {
		return err
	}

	if opts.roleARN == "" {
		return writeCredentials(credsFromBase(baseSession), opts.format)
	}

	assumed, err := prepareAssumedSession(ctx, store, baseSession, opts)
	if err != nil {
		return err
	}
	return writeCredentials(credsFromAssumed(assumed), opts.format)
}

// prepareBaseSession returns a valid (non-expiring-soon) login_session,
// refreshing or invoking auto-login as needed.
func prepareBaseSession(ctx context.Context, store *keychain.Store, profile string, autoLogin bool) (*keychain.Session, error) {
	sess, err := store.Load(profile)
	switch {
	case errors.Is(err, keychain.ErrNotFound):
		return bootstrapBaseSession(ctx, store, profile, autoLogin)
	case err != nil:
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

	sess, err = store.Load(profile)
	if err != nil {
		return nil, err
	}
	if time.Until(sess.Expiration) > refreshThreshold {
		return sess, nil
	}

	return refreshBaseSession(ctx, store, profile, sess, autoLogin)
}

func refreshBaseSession(ctx context.Context, store *keychain.Store, profile string, prev *keychain.Session, autoLogin bool) (*keychain.Session, error) {
	cfg, err := awsconfig.NewAWSConfig(ctx, prev.Region)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}
	refreshed, err := loginflow.Refresh(ctx, cfg, &loginflow.LoginResult{
		RefreshToken: prev.RefreshToken,
		DPoPKeyPEM:   prev.DPoPKeyPEM,
		SessionARN:   prev.SessionARN,
		Region:       prev.Region,
		ClientID:     prev.ClientID,
	})
	if err == nil {
		sess := sessionFromLoginResult(refreshed)
		if err := store.Save(profile, sess); err != nil {
			return nil, fmt.Errorf("save refreshed session: %w", err)
		}
		return sess, nil
	}

	if loginflow.IsReloginRequired(err) && autoLogin {
		return runAutoLogin(ctx, store, profile, prev.Region)
	}
	if loginflow.IsReloginRequired(err) {
		return nil, fmt.Errorf("refresh failed (%w); run: aws-login-vault login --profile %s (or pass --auto-login)", err, profile)
	}
	return nil, fmt.Errorf("refresh failed: %w", err)
}

// bootstrapBaseSession is called when no session exists yet for the profile.
// Without --auto-login we refuse; with it we enter the SSH-gated login flow.
func bootstrapBaseSession(ctx context.Context, store *keychain.Store, profile string, autoLogin bool) (*keychain.Session, error) {
	if !autoLogin {
		return nil, fmt.Errorf("profile %q is not logged in; run: aws-login-vault login --profile %s (or pass --auto-login)", profile, profile)
	}

	pl, err := lock.AcquireProfile(profile, refreshLockTimeout)
	if err != nil {
		return nil, fmt.Errorf("lock profile %q: %w", profile, err)
	}
	defer func() { _ = pl.Release() }()

	if sess, err := store.Load(profile); err == nil && time.Until(sess.Expiration) > refreshThreshold {
		return sess, nil
	}
	region, err := awsconfig.ResolveRegion(ctx, profile, "")
	if err != nil {
		return nil, err
	}
	return runAutoLogin(ctx, store, profile, region)
}

func runAutoLogin(ctx context.Context, store *keychain.Store, profile, region string) (*keychain.Session, error) {
	if isSSHSession() {
		return nil, fmt.Errorf("auto-login cannot reach a local browser in a remote SSH session; run: aws-login-vault login --profile %s on your local machine", profile)
	}
	cfg, err := awsconfig.NewAWSConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}
	result, err := loginflow.SameDeviceLogin(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sess := sessionFromLoginResult(result)
	if err := store.Save(profile, sess); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}
	return sess, nil
}

func isSSHSession() bool {
	return os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""
}

// prepareAssumedSession handles the --role path: check cache, AssumeRole if
// expired or missing, persist under the assumed-key, and return the result.
func prepareAssumedSession(ctx context.Context, store *keychain.Store, base *keychain.Session, opts exportOptions) (*keychain.AssumedSession, error) {
	sourceIdentity, err := resolveSourceIdentity(opts.sourceIdentity, base.SessionARN)
	if err != nil {
		return nil, err
	}
	cacheKey := keychain.AssumedKey(opts.profile, opts.roleARN, sourceIdentity)

	if cached, err := store.LoadAssumed(cacheKey); err == nil {
		if time.Until(cached.Expiration) > loginflow.AssumedExpiryWindow {
			return cached, nil
		}
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	pl, err := lock.AcquireProfile(opts.profile, refreshLockTimeout)
	if err != nil {
		return nil, fmt.Errorf("lock profile %q: %w", opts.profile, err)
	}
	defer func() { _ = pl.Release() }()

	if cached, err := store.LoadAssumed(cacheKey); err == nil {
		if time.Until(cached.Expiration) > loginflow.AssumedExpiryWindow {
			return cached, nil
		}
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	cfg, err := awsconfig.NewAWSConfig(ctx, base.Region)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}

	out, err := loginflow.AssumeRole(ctx, loginflow.AssumeRoleInput{
		Config: cfg,
		BaseCredentials: aws.Credentials{
			AccessKeyID:     base.AccessKeyID,
			SecretAccessKey: base.SecretAccessKey,
			SessionToken:    base.SessionToken,
		},
		RoleARN:         opts.roleARN,
		RoleSessionName: opts.roleSessionName,
		SourceIdentity:  sourceIdentity,
		Duration:        opts.roleDuration,
		SubARN:          base.SessionARN,
	})
	if err != nil {
		return nil, assumeRoleErrorWithHint(err, sourceIdentity)
	}

	sess := &keychain.AssumedSession{
		AccessKeyID:     out.AccessKeyID,
		SecretAccessKey: out.SecretAccessKey,
		SessionToken:    out.SessionToken,
		Expiration:      out.Expiration,
		RoleARN:         opts.roleARN,
		RoleSessionName: out.RoleSessionName,
		SourceIdentity:  out.SourceIdentity,
		Region:          base.Region,
	}
	if err := store.SaveAssumed(cacheKey, sess); err != nil {
		return nil, fmt.Errorf("save assumed session: %w", err)
	}
	return sess, nil
}

func resolveSourceIdentity(raw, subARN string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if raw != sourceIdentityAuto {
		return raw, nil
	}
	derived := loginflow.DeriveRoleSessionName(subARN) // same sanitize rules
	if derived == "" {
		return "", fmt.Errorf(`could not derive source-identity from %q; pass --source-identity <value> explicitly`, subARN)
	}
	return derived, nil
}

// assumeRoleErrorWithHint surfaces the SourceIdentity trust-policy gotcha when
// relevant.
func assumeRoleErrorWithHint(err error, sourceIdentity string) error {
	if sourceIdentity == "" {
		return err
	}
	msg := err.Error()
	if strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "sts:SetSourceIdentity") {
		return fmt.Errorf("%w; if the role's trust policy does not grant sts:SetSourceIdentity, drop --source-identity", err)
	}
	return err
}

type exportCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	Region          string
}

func credsFromBase(s *keychain.Session) exportCreds {
	return exportCreds{
		AccessKeyID:     s.AccessKeyID,
		SecretAccessKey: s.SecretAccessKey,
		SessionToken:    s.SessionToken,
		Expiration:      s.Expiration,
		Region:          s.Region,
	}
}

func credsFromAssumed(s *keychain.AssumedSession) exportCreds {
	return exportCreds{
		AccessKeyID:     s.AccessKeyID,
		SecretAccessKey: s.SecretAccessKey,
		SessionToken:    s.SessionToken,
		Expiration:      s.Expiration,
		Region:          s.Region,
	}
}

func writeCredentials(c exportCreds, format string) error {
	switch format {
	case formatJSON:
		return writeJSON(c)
	case formatEnv:
		return writeEnv(c)
	}
	return fmt.Errorf("unknown format %q", format)
}

func writeJSON(c exportCreds) error {
	out := credentialProcessOutput{
		Version:         1,
		AccessKeyId:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Expiration:      c.Expiration.UTC().Format(time.RFC3339),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeEnv(c exportCreds) error {
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", shellQuote(c.AccessKeyID))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", shellQuote(c.SecretAccessKey))
	if c.SessionToken != "" {
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", shellQuote(c.SessionToken))
	}
	fmt.Printf("export AWS_CREDENTIAL_EXPIRATION=%s\n", shellQuote(c.Expiration.UTC().Format(time.RFC3339)))
	if c.Region != "" {
		fmt.Printf("export AWS_REGION=%s\n", shellQuote(c.Region))
		fmt.Printf("export AWS_DEFAULT_REGION=%s\n", shellQuote(c.Region))
	}
	return nil
}

// shellQuote wraps a value in single quotes, escaping embedded quotes so the
// output is safe to paste into bash/zsh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
