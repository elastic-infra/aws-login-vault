package lock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// Profile is a held exclusive advisory lock on a profile. Release after use.
type Profile struct {
	fl *flock.Flock
}

func lockDir() (string, error) {
	// Cache dir fits ephemeral state: locks are reconstructible and harmless to lose.
	// Maps to ~/Library/Caches on macOS, $XDG_CACHE_HOME on Linux, %LocalAppData% on Windows.
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "aws-login-vault", "locks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// AcquireProfile blocks until the lock is obtained or the timeout expires.
// Serialises refresh and login across concurrent aws-login-vault processes so
// they cannot race on refresh-token rotation or duplicate-login the same profile.
func AcquireProfile(ctx context.Context, profile string, timeout time.Duration) (*Profile, error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, profile+".lock")
	fl := flock.New(path)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	locked, err := fl.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("acquire lock %s: %w", path, err)
	}
	if !locked {
		return nil, errors.New("lock not acquired within timeout")
	}
	return &Profile{fl: fl}, nil
}

func (p *Profile) Release() error {
	if p == nil || p.fl == nil {
		return nil
	}
	return p.fl.Unlock()
}
