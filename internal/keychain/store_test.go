package keychain

import (
	"strings"
	"testing"

	"github.com/99designs/keyring"
)

func TestAssumedKey(t *testing.T) {
	// Pre-computed sha256("arn:aws:iam::123456789012:role/Foo")
	// verified via: echo -n "..." | shasum -a 256
	const roleArnSha256 = "ac8836fdff42e91cd4f3d22a0efc38b2d091f2cf63ca6a862becd96f4fa7e1a5"

	tests := []struct {
		name     string
		profile  string
		role     string
		identity string
		want     string
	}{
		{
			name:    "no source identity",
			profile: "dev",
			role:    "arn:aws:iam::123456789012:role/Foo",
			want:    "assumed/dev/" + roleArnSha256,
		},
		{
			name:     "with source identity",
			profile:  "dev",
			role:     "arn:aws:iam::123456789012:role/Foo",
			identity: "alice",
			want:     "assumed/dev/" + roleArnSha256 + "/alice",
		},
		{
			name:     "different profile",
			profile:  "prod",
			role:     "arn:aws:iam::123456789012:role/Foo",
			identity: "alice",
			want:     "assumed/prod/" + roleArnSha256 + "/alice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssumedKey(tt.profile, tt.role, tt.identity)
			if got != tt.want {
				t.Errorf("AssumedKey = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseBackend(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    keyring.BackendType
		wantErr bool
	}{
		{name: "empty falls back to auto", in: "", want: ""},
		{name: "keychain", in: "keychain", want: keyring.KeychainBackend},
		{name: "secret-service", in: "secret-service", want: keyring.SecretServiceBackend},
		{name: "pass", in: "pass", want: keyring.PassBackend},
		{name: "keyctl", in: "keyctl", want: keyring.KeyCtlBackend},
		{name: "unsupported wincred", in: "wincred", wantErr: true},
		{name: "trailing whitespace not normalized", in: "keychain ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBackend(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBackend(%q): want error, got nil", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBackend(%q): unexpected error %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseBackend(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAssumedKey_DifferentRolesProduceDifferentHashes(t *testing.T) {
	a := AssumedKey("dev", "arn:aws:iam::1:role/A", "")
	b := AssumedKey("dev", "arn:aws:iam::1:role/B", "")
	if a == b {
		t.Errorf("expected different keys, got identical: %s", a)
	}
	if !strings.HasPrefix(a, "assumed/dev/") || !strings.HasPrefix(b, "assumed/dev/") {
		t.Errorf("missing assumed/dev/ prefix: %s, %s", a, b)
	}
}
