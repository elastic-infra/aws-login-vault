package login

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVerificationCode(t *testing.T) {
	encStd := base64.StdEncoding.EncodeToString
	encURL := base64.URLEncoding.EncodeToString

	tests := []struct {
		name      string
		input     string
		wantCode  string
		wantState string
		wantErr   bool
	}{
		{
			name:      "valid standard base64",
			input:     encStd([]byte("state=abc123&code=def456")),
			wantCode:  "def456",
			wantState: "abc123",
		},
		{
			name:      "valid url-safe base64",
			input:     encURL([]byte("state=abc&code=zzz")),
			wantCode:  "zzz",
			wantState: "abc",
		},
		{
			name:      "trailing newline and spaces are trimmed",
			input:     "  " + encStd([]byte("state=s&code=c")) + "\n",
			wantCode:  "c",
			wantState: "s",
		},
		{
			name:      "url-encoded value in query string",
			input:     encStd([]byte("state=ssn&code=" + "a%2Fb")),
			wantCode:  "a/b",
			wantState: "ssn",
		},
		{
			name:    "garbage base64",
			input:   "!!!not-base64!!!",
			wantErr: true,
		},
		{
			name:    "missing state",
			input:   encStd([]byte("code=onlycode")),
			wantErr: true,
		},
		{
			name:    "missing code",
			input:   encStd([]byte("state=onlystate")),
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   \n\t",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, state, err := parseVerificationCode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
			if state != tt.wantState {
				t.Errorf("state = %q, want %q", state, tt.wantState)
			}
		})
	}
}

func TestDecodeBase64Permissive_FallsThroughVariants(t *testing.T) {
	payload := []byte("state=s&code=c")

	tests := []struct {
		name string
		enc  func([]byte) string
	}{
		{"StdEncoding", base64.StdEncoding.EncodeToString},
		{"URLEncoding", base64.URLEncoding.EncodeToString},
		{"RawStdEncoding", base64.RawStdEncoding.EncodeToString},
		{"RawURLEncoding", base64.RawURLEncoding.EncodeToString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := decodeBase64Permissive(tt.enc(payload))
			if err != nil {
				t.Fatalf("decodeBase64Permissive: %v", err)
			}
			if !strings.Contains(string(out), "state=s") {
				t.Errorf("unexpected decode output: %q", out)
			}
		})
	}
}
