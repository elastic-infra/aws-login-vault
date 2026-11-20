package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/elastic-infra/aws-login-vault/internal/keychain"
)

func TestSaveSessionWithGuard(t *testing.T) {
	const sentinelRefreshToken = "after-save"

	tests := []struct {
		name    string
		prev    *keychain.Session
		newARN  string
		force   bool
		wantErr error
	}{
		{
			name:   "first save (prev=nil)",
			prev:   nil,
			newARN: "arn:aws:sts::111111111111:assumed-role/A/user",
			force:  false,
		},
		{
			name:   "same ARN",
			prev:   &keychain.Session{SessionARN: "arn:aws:sts::111111111111:assumed-role/A/user"},
			newARN: "arn:aws:sts::111111111111:assumed-role/A/user",
			force:  false,
		},
		{
			name:   "different ARN with force",
			prev:   &keychain.Session{SessionARN: "arn:aws:sts::111111111111:assumed-role/A/user"},
			newARN: "arn:aws:sts::222222222222:assumed-role/B/user",
			force:  true,
		},
		{
			name:    "different ARN without force",
			prev:    &keychain.Session{SessionARN: "arn:aws:sts::111111111111:assumed-role/A/user"},
			newARN:  "arn:aws:sts::222222222222:assumed-role/B/user",
			force:   false,
			wantErr: ErrSessionARNMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := keychain.NewForTesting()
			if tt.prev != nil {
				if err := store.Save("default", tt.prev); err != nil {
					t.Fatalf("seed prev: %v", err)
				}
			}
			newSess := &keychain.Session{SessionARN: tt.newARN, RefreshToken: sentinelRefreshToken}
			err := saveSessionWithGuard(store, "default", tt.prev, newSess, tt.force)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want errors.Is(%v)", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.prev.SessionARN) || !strings.Contains(err.Error(), tt.newARN) {
					t.Errorf("err message = %q, want both %q and %q in message", err.Error(), tt.prev.SessionARN, tt.newARN)
				}
				got, loadErr := store.Load("default")
				if loadErr != nil {
					t.Fatalf("load after guarded reject: %v", loadErr)
				}
				if got.SessionARN != tt.prev.SessionARN {
					t.Errorf("store overwritten: got %q, want %q", got.SessionARN, tt.prev.SessionARN)
				}
				if got.RefreshToken == sentinelRefreshToken {
					t.Errorf("store overwritten with new session despite guard rejection")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			got, err := store.Load("default")
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got.SessionARN != tt.newARN {
				t.Errorf("got SessionARN %q, want %q", got.SessionARN, tt.newARN)
			}
			if got.RefreshToken != sentinelRefreshToken {
				t.Errorf("store not updated: RefreshToken = %q, want %q", got.RefreshToken, sentinelRefreshToken)
			}
		})
	}
}

func TestSessionEnded(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		end  time.Time
		want bool
	}{
		{"unknown", time.Time{}, false},
		{"well before end", now.Add(time.Hour), false},
		{"within refresh threshold", now.Add(refreshThreshold - time.Second), false},
		{"one second before end", now.Add(time.Second), false},
		{"at end", now, true},
		{"past end", now.Add(-time.Minute), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &keychain.Session{SessionExpiration: tt.end}
			if got := sessionEnded(sess, now); got != tt.want {
				t.Errorf("sessionEnded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		end  time.Time
		exp  time.Time
		want bool
	}{
		{"fresh, unknown end", time.Time{}, now.Add(10 * time.Minute), false},
		{"expiring, unknown end", time.Time{}, now.Add(30 * time.Second), true},
		{"expiring, end far away", now.Add(time.Hour), now.Add(30 * time.Second), true},
		{"capped to end within threshold", now.Add(30 * time.Second), now.Add(30 * time.Second), false},
		{"capped to end at threshold", now.Add(refreshThreshold), now.Add(refreshThreshold), false},
		{"near end, credentials expired", now.Add(30 * time.Second), now.Add(-time.Second), true},
		{"past end", now.Add(-time.Second), now.Add(-time.Second), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &keychain.Session{SessionExpiration: tt.end, Expiration: tt.exp}
			if got := needsRefresh(sess, now); got != tt.want {
				t.Errorf("needsRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}
