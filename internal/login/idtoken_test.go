package login

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// buildJWT produces a JWT-shaped token with the given payload claims.
// The header and signature segments are filler; ExtractSubFromIDToken does
// not verify signatures, so they only need to look like base64url.
func buildJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	pl, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "aGVhZGVy." + base64.RawURLEncoding.EncodeToString(pl) + ".c2ln"
}

func TestExtractSubFromIDToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid IAM user arn",
			token: buildJWT(t, map[string]any{"sub": "arn:aws:iam::123456789012:user/alice"}),
			want:  "arn:aws:iam::123456789012:user/alice",
		},
		{
			name:  "valid signin session arn",
			token: buildJWT(t, map[string]any{"sub": "arn:aws:signin::123456789012:session/abc"}),
			want:  "arn:aws:signin::123456789012:session/abc",
		},
		{
			name:    "missing sub",
			token:   buildJWT(t, map[string]any{"aud": "x"}),
			wantErr: true,
		},
		{
			name:    "empty sub",
			token:   buildJWT(t, map[string]any{"sub": ""}),
			wantErr: true,
		},
		{
			name:    "two segments only",
			token:   "header.payload",
			wantErr: true,
		},
		{
			name:    "payload not valid JSON",
			token:   "aaa." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sss",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractSubFromIDToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExtractSubFromIDToken_PaddingFallback covers the URL-safe base64 with
// padding fallback path: some JWT producers emit padding even though the spec
// forbids it. The fallback lets us parse either encoding.
func TestExtractSubFromIDToken_PaddingFallback(t *testing.T) {
	payload := []byte(`{"sub":"arn:aws:iam::1:user/x"}`)
	// base64.URLEncoding (with padding).
	encoded := base64.URLEncoding.EncodeToString(payload)
	token := "aaa." + encoded + ".ccc"

	got, err := ExtractSubFromIDToken(token)
	if err != nil {
		t.Fatalf("ExtractSubFromIDToken: %v", err)
	}
	if got != "arn:aws:iam::1:user/x" {
		t.Errorf("got %q, want arn:aws:iam::1:user/x", got)
	}
}
