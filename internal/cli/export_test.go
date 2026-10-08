package cli

import (
	"errors"
	"fmt"
	"testing"

	smithy "github.com/aws/smithy-go"
)

func TestIsExpiredToken(t *testing.T) {
	expired := &smithy.GenericAPIError{Code: "ExpiredToken", Message: "The security token included in the request is expired"}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "expired token", err: expired, want: true},
		{name: "wrapped expired token", err: fmt.Errorf("operation error STS: AssumeRole: %w", expired), want: true},
		{name: "access denied", err: &smithy.GenericAPIError{Code: "AccessDenied"}, want: false},
		{name: "non api error", err: errors.New("ExpiredToken"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpiredToken(tt.err); got != tt.want {
				t.Errorf("isExpiredToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
