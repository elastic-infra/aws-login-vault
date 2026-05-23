package cli

import (
	"errors"
	"testing"

	"github.com/hkobayash/aws-login-vault/internal/keychain"
)

func TestSaveSessionWithGuard(t *testing.T) {
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
			newSess := &keychain.Session{SessionARN: tt.newARN}
			err := saveSessionWithGuard(store, "default", tt.prev, newSess, tt.force)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want errors.Is(%v)", err, tt.wantErr)
				}
				got, loadErr := store.Load("default")
				if loadErr != nil {
					t.Fatalf("load after guarded reject: %v", loadErr)
				}
				if got.SessionARN != tt.prev.SessionARN {
					t.Errorf("store overwritten: got %q, want %q", got.SessionARN, tt.prev.SessionARN)
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
				t.Errorf("got %q, want %q", got.SessionARN, tt.newARN)
			}
		})
	}
}
