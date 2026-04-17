package login

import (
	"strings"
	"testing"
)

func TestPEMRoundTrip(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"sample 1"},
		{"sample 2"},
		{"sample 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewDPoPKey()
			if err != nil {
				t.Fatalf("NewDPoPKey: %v", err)
			}
			encoded, err := SerializeECPrivateKeyPEM(key)
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			if !strings.HasPrefix(encoded, "-----BEGIN EC PRIVATE KEY-----") {
				t.Errorf("PEM header missing: %q", encoded)
			}
			decoded, err := ParseECPrivateKeyPEM(encoded)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if key.D.Cmp(decoded.D) != 0 {
				t.Error("D mismatch after round-trip")
			}
			if key.PublicKey.X.Cmp(decoded.PublicKey.X) != 0 ||
				key.PublicKey.Y.Cmp(decoded.PublicKey.Y) != 0 {
				t.Error("public key mismatch after round-trip")
			}
		})
	}
}

func TestParseECPrivateKeyPEM_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"not a PEM at all", "definitely not a pem"},
		{"wrong block type", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"},
		{"right type, corrupt body", "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseECPrivateKeyPEM(tt.input); err == nil {
				t.Errorf("expected error for %q, got nil", tt.input)
			}
		})
	}
}
