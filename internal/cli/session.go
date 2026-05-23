package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/hkobayash/aws-login-vault/internal/awsconfig"
	"github.com/hkobayash/aws-login-vault/internal/keychain"
	loginflow "github.com/hkobayash/aws-login-vault/internal/login"
)

// ErrSessionARNMismatch is returned when saving would change the SessionARN of
// an existing profile without --force. Callers wrap this with context-specific
// remediation hints (login vs. auto-login).
var ErrSessionARNMismatch = errors.New("session ARN mismatch")

func sessionFromLoginResult(r *loginflow.LoginResult) *keychain.Session {
	return &keychain.Session{
		SessionARN:      r.SessionARN,
		AccessKeyID:     r.AccessKeyID,
		SecretAccessKey: r.SecretAccessKey,
		SessionToken:    r.SessionToken,
		Expiration:      r.Expiration,
		RefreshToken:    r.RefreshToken,
		DPoPKeyPEM:      r.DPoPKeyPEM,
		Region:          r.Region,
		ClientID:        r.ClientID,
	}
}

// saveSessionWithGuard persists next under profile, refusing to overwrite an
// existing entry whose SessionARN differs from prev unless force is set.
// Callers must hold the profile flock and pass a freshly loaded prev — the
// guard trusts the caller-supplied pointer and does not re-read the store.
// refreshBaseSession's happy path intentionally bypasses this guard because
// a successful OAuth refresh against the same refresh token typically
// returns the same sub. If that assumption proves false in practice, route
// refresh through this helper as well.
func saveSessionWithGuard(store *keychain.Store, profile string, prev, next *keychain.Session, force bool) error {
	if prev != nil && prev.SessionARN != next.SessionARN && !force {
		return fmt.Errorf("%w: profile %q was %s, but got %s",
			ErrSessionARNMismatch, profile, prev.SessionARN, next.SessionARN)
	}
	if err := store.Save(profile, next); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

type browserLoginOptions struct {
	profile string
	region  string
	prev    *keychain.Session
	force   bool
	remote  bool
}

// performBrowserLogin runs the SAME_DEVICE or CROSS_DEVICE OAuth flow and
// persists the resulting session through saveSessionWithGuard.
func performBrowserLogin(ctx context.Context, store *keychain.Store, opts browserLoginOptions) (*keychain.Session, error) {
	cfg, err := awsconfig.NewAWSConfig(ctx, opts.region)
	if err != nil {
		return nil, fmt.Errorf("build aws config: %w", err)
	}

	var result *loginflow.LoginResult
	if opts.remote {
		result, err = loginflow.CrossDeviceLogin(ctx, cfg, stdinReadVerificationCode)
	} else {
		result, err = loginflow.SameDeviceLogin(ctx, cfg)
	}
	if err != nil {
		return nil, err
	}

	sess := sessionFromLoginResult(result)
	if err := saveSessionWithGuard(store, opts.profile, opts.prev, sess, opts.force); err != nil {
		return nil, err
	}
	return sess, nil
}
