package sts

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	smithy "github.com/aws/smithy-go"
)

func TestDeriveRoleSessionName(t *testing.T) {
	tests := []struct {
		name string
		sub  string
		want string
	}{
		{"iam user", "arn:aws:iam::123456789012:user/alice", "alice"},
		{"iam user with dot", "arn:aws:iam::123456789012:user/hirotake.kobayashi", "hirotake.kobayashi"},
		{"iam user with email", "arn:aws:iam::123456789012:user/alice@example.com", "alice@example.com"},
		{"assumed role", "arn:aws:sts::123456789012:assumed-role/MyRole/SessionID", "SessionID"},
		{"federated user", "arn:aws:sts::123456789012:federated-user/charlie", "charlie"},
		{"unsupported iam role arn", "arn:aws:iam::123456789012:role/SomeRole", ""},
		{"empty", "", ""},
		{"no colon", "not-an-arn", ""},
		{"colon at end", "arn:aws:iam::123:", ""},
		{"very long user name gets truncated to 64", "arn:aws:iam::123:user/" + strings.Repeat("x", 80), strings.Repeat("x", 64)},
		{"illegal chars replaced with underscore", "arn:aws:iam::123:user/a*b!c~d", "a_b_c_d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveRoleSessionName(tt.sub)
			if got != tt.want {
				t.Errorf("DeriveRoleSessionName(%q) = %q, want %q", tt.sub, got, tt.want)
			}
		})
	}
}

func TestSanitizeSessionName_Length(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantLen int
	}{
		{"short", "abc", 3},
		{"exactly 64", strings.Repeat("a", 64), 64},
		{"65 chars truncated", strings.Repeat("a", 65), 64},
		{"128 chars truncated", strings.Repeat("a", 128), 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeSessionName(tt.in)
			if len(got) != tt.wantLen {
				t.Errorf("len(sanitizeSessionName(%d-char input)) = %d, want %d", len(tt.in), len(got), tt.wantLen)
			}
		})
	}
}

func TestIsExpiredToken(t *testing.T) {
	expired := &smithy.GenericAPIError{Code: "ExpiredToken", Message: "The security token included in the request is expired"}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"expired token", expired, true},
		{"wrapped expired token", fmt.Errorf("operation error STS: AssumeRole: %w", expired), true},
		{"access denied", &smithy.GenericAPIError{Code: "AccessDenied"}, false},
		{"non api error", errors.New("ExpiredToken"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExpiredToken(tt.err); got != tt.want {
				t.Errorf("IsExpiredToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
