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
	smithy "github.com/aws/smithy-go"
	"github.com/spf13/cobra"

	"github.com/elastic-infra/aws-login-vault/internal/awsconfig"
	"github.com/elastic-infra/aws-login-vault/internal/keychain"
	"github.com/elastic-infra/aws-login-vault/internal/lock"
	loginflow "github.com/elastic-infra/aws-login-vault/internal/login"
	"github.com/elastic-infra/aws-login-vault/internal/sts"
)

const (
	refreshThreshold   = 60 * time.Second
	refreshLockTimeout = 30 * time.Second
	expiredBaseRetries = 2

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

// exportable is implemented by *keychain.Session and *keychain.AssumedSession;
// it lets writeJSON/writeEnv handle either without a middle-man struct.
type exportable interface {
	Creds() (akid, secret, token string, expiration time.Time, region string)
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

func newExportCmd(sf *storeFlags) *cobra.Command {
	opts := exportOptions{}
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Print credentials for a profile (for credential_process or shell use)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(cmd.Context(), sf, opts)
		},
	}
	registerCredentialFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.format, "format", formatJSON, "output format: json | env")
	return cmd
}

// registerCredentialFlags registers the flags shared by export and server:
// profile selection plus the AssumeRole / auto-login knobs.
func registerCredentialFlags(cmd *cobra.Command, opts *exportOptions) {
	cmd.Flags().StringVar(&opts.profile, "profile", defaultProfile, "profile name")
	cmd.Flags().StringVar(&opts.roleARN, "role", "", "role ARN to assume (enables AssumeRole mode)")
	cmd.Flags().StringVar(&opts.roleSessionName, "role-session-name", "", "RoleSessionName override (default: derived from sub)")
	cmd.Flags().StringVar(&opts.sourceIdentity, "source-identity", "", `SourceIdentity for AssumeRole. "auto" derives from sub; any other value is sent literally`)
	cmd.Flags().DurationVar(&opts.roleDuration, "role-duration", 0, "AssumeRole DurationSeconds (default 1h)")
	cmd.Flags().BoolVar(&opts.autoLogin, "auto-login", os.Getenv(envAutoLogin) == "1",
		"run login automatically if the profile is not authenticated (requires a local GUI session)")
}

func runExport(ctx context.Context, sf *storeFlags, opts exportOptions) error {
	if opts.format != formatJSON && opts.format != formatEnv {
		return fmt.Errorf("unknown --format %q (expected json or env)", opts.format)
	}

	store, err := openStore(sf)
	if err != nil {
		return err
	}

	creds, err := resolveCredentials(ctx, store, opts)
	if err != nil {
		return err
	}
	return writeCredentials(creds, opts.format)
}

// resolveCredentials returns the credentials to hand out for opts: the base
// login session, or the assumed-role session when --role is set. Shared by
// export and the server command.
func resolveCredentials(ctx context.Context, store *keychain.Store, opts exportOptions) (exportable, error) {
	for attempt := 0; ; attempt++ {
		base, err := prepareBaseSession(ctx, store, opts.profile, opts.autoLogin)
		if err != nil {
			return nil, err
		}
		if opts.roleARN == "" {
			return base, nil
		}
		assumed, err := prepareAssumedSession(ctx, store, base, opts)
		if err == nil {
			return assumed, nil
		}
		if !sts.IsExpiredToken(err) || attempt == expiredBaseRetries {
			return nil, err
		}
		if err := invalidateBaseSession(ctx, store, opts.profile, base); err != nil {
			return nil, err
		}
	}
}

// invalidateBaseSession marks the stored login session expired so the next
// prepareBaseSession refreshes it, unless another process already replaced it.
func invalidateBaseSession(ctx context.Context, store *keychain.Store, profile string, stale *keychain.Session) error {
	pl, err := lock.AcquireProfile(ctx, profile, refreshLockTimeout)
	if err != nil {
		return fmt.Errorf("lock profile %q: %w", profile, err)
	}
	defer func() { _ = pl.Release() }()

	sess, err := store.Load(profile)
	if err != nil {
		return err
	}
	if sess.AccessKeyID != stale.AccessKeyID {
		return nil
	}
	sess.Expiration = time.Time{}
	return store.Save(profile, sess)
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

	pl, err := lock.AcquireProfile(ctx, profile, refreshLockTimeout)
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
		return runAutoLogin(ctx, store, profile, prev.Region, prev)
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

	pl, err := lock.AcquireProfile(ctx, profile, refreshLockTimeout)
	if err != nil {
		return nil, fmt.Errorf("lock profile %q: %w", profile, err)
	}
	defer func() { _ = pl.Release() }()

	var prev *keychain.Session
	sess, err := store.Load(profile)
	if err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}
	if sess != nil {
		if time.Until(sess.Expiration) > refreshThreshold {
			return sess, nil
		}
		prev = sess
	}
	region, err := awsconfig.ResolveRegion(ctx, profile, "")
	if err != nil {
		return nil, err
	}
	return runAutoLogin(ctx, store, profile, region, prev)
}

func runAutoLogin(ctx context.Context, store *keychain.Store, profile, region string, prev *keychain.Session) (*keychain.Session, error) {
	if isSSHSession() {
		return nil, fmt.Errorf("auto-login cannot reach a local browser in a remote SSH session; run: aws-login-vault login --profile %s on your local machine", profile)
	}
	sess, err := performBrowserLogin(ctx, store, browserLoginOptions{
		profile: profile,
		region:  region,
		prev:    prev,
		force:   false,
		remote:  false,
	})
	if err != nil {
		if errors.Is(err, ErrSessionARNMismatch) {
			return nil, fmt.Errorf("%w; recover with: aws-login-vault login --profile %s --force, or aws-login-vault logout --profile %s first", err, profile, profile)
		}
		return nil, err
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
		if time.Until(cached.Expiration) > sts.AssumedExpiryWindow {
			return cached, nil
		}
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	pl, err := lock.AcquireProfile(ctx, opts.profile, refreshLockTimeout)
	if err != nil {
		return nil, fmt.Errorf("lock profile %q: %w", opts.profile, err)
	}
	defer func() { _ = pl.Release() }()

	if cached, err := store.LoadAssumed(cacheKey); err == nil {
		if time.Until(cached.Expiration) > sts.AssumedExpiryWindow {
			return cached, nil
		}
	} else if !errors.Is(err, keychain.ErrNotFound) {
		return nil, err
	}

	cfg, err := awsconfig.NewAWSConfig(ctx, base.Region)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}

	out, err := sts.AssumeRole(ctx, sts.AssumeRoleInput{
		Config: cfg,
		Base: sts.BaseSession{
			Credentials: aws.Credentials{
				AccessKeyID:     base.AccessKeyID,
				SecretAccessKey: base.SecretAccessKey,
				SessionToken:    base.SessionToken,
			},
			SessionARN: base.SessionARN,
		},
		RoleARN:         opts.roleARN,
		RoleSessionName: opts.roleSessionName,
		SourceIdentity:  sourceIdentity,
		Duration:        opts.roleDuration,
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
	derived := sts.DeriveRoleSessionName(subARN)
	if derived == "" {
		return "", fmt.Errorf(`could not derive source-identity from %q; pass --source-identity <value> explicitly`, subARN)
	}
	return derived, nil
}

// assumeRoleErrorWithHint surfaces the SourceIdentity trust-policy gotcha when
// the server returned AccessDenied citing SetSourceIdentity.
func assumeRoleErrorWithHint(err error, sourceIdentity string) error {
	if sourceIdentity == "" {
		return err
	}
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok && apiErr.ErrorCode() == "AccessDenied" {
		if strings.Contains(apiErr.ErrorMessage(), "SetSourceIdentity") {
			return fmt.Errorf("%w; the role's trust policy must allow sts:SetSourceIdentity, or drop --source-identity", err)
		}
	}
	return err
}

func writeCredentials(c exportable, format string) error {
	switch format {
	case formatJSON:
		return writeJSON(c)
	case formatEnv:
		return writeEnv(c)
	}
	return fmt.Errorf("unknown format %q", format)
}

func writeJSON(c exportable) error {
	akid, secret, token, expiration, _ := c.Creds()
	out := credentialProcessOutput{
		Version:         1,
		AccessKeyId:     akid,
		SecretAccessKey: secret,
		SessionToken:    token,
		Expiration:      expiration.UTC().Format(time.RFC3339),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeEnv(c exportable) error {
	akid, secret, token, expiration, region := c.Creds()
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", akid)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", secret)
	if token != "" {
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", token)
	}
	fmt.Printf("export AWS_CREDENTIAL_EXPIRATION=%s\n", expiration.UTC().Format(time.RFC3339))
	if region != "" {
		fmt.Printf("export AWS_REGION=%s\n", region)
		fmt.Printf("export AWS_DEFAULT_REGION=%s\n", region)
	}
	return nil
}
