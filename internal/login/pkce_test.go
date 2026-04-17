package login

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewPKCE_Properties(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T, verifier, challenge string)
	}{
		{
			name: "verifier length is 64",
			check: func(t *testing.T, verifier, _ string) {
				if got := len(verifier); got != verifierLength {
					t.Errorf("len(verifier) = %d, want %d", got, verifierLength)
				}
			},
		},
		{
			name: "verifier uses only RFC 7636 unreserved alphabet",
			check: func(t *testing.T, verifier, _ string) {
				for i := 0; i < len(verifier); i++ {
					if !strings.ContainsRune(verifierAlphabet, rune(verifier[i])) {
						t.Errorf("byte %q at index %d not in alphabet", verifier[i], i)
					}
				}
			},
		},
		{
			name: "challenge equals base64url(sha256(verifier)) without padding",
			check: func(t *testing.T, verifier, challenge string) {
				sum := sha256.Sum256([]byte(verifier))
				want := base64.RawURLEncoding.EncodeToString(sum[:])
				if challenge != want {
					t.Errorf("challenge = %q, want %q", challenge, want)
				}
				if strings.HasSuffix(challenge, "=") {
					t.Errorf("challenge has '=' padding: %q", challenge)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, c, err := NewPKCE()
			if err != nil {
				t.Fatalf("NewPKCE: %v", err)
			}
			tt.check(t, v, c)
		})
	}
}

func TestNewPKCE_UniqueAcrossCalls(t *testing.T) {
	const n = 32
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		v, _, err := NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE: %v", err)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate verifier at iter %d: %s", i, v)
		}
		seen[v] = struct{}{}
	}
}

// TestNewPKCE_NoModuloBias asserts that the alphabet is sampled without the
// bias that the naive `randByte % 66` construction would introduce. A 20%
// tolerance is loose enough to virtually never flake on cryptographically
// strong randomness while still catching any regression that reintroduces
// biased sampling.
func TestNewPKCE_NoModuloBias(t *testing.T) {
	const samples = 5000
	counts := make(map[byte]int, len(verifierAlphabet))
	for i := 0; i < samples; i++ {
		v, _, err := NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE: %v", err)
		}
		for j := 0; j < len(v); j++ {
			counts[v[j]]++
		}
	}
	total := float64(samples * verifierLength)
	expected := total / float64(len(verifierAlphabet))
	const tolerance = 0.20
	lo, hi := expected*(1-tolerance), expected*(1+tolerance)

	for i := 0; i < len(verifierAlphabet); i++ {
		b := verifierAlphabet[i]
		got := float64(counts[b])
		if got < lo || got > hi {
			t.Errorf("char %q count=%d outside ±%.0f%% of expected %.0f (range %.0f..%.0f)",
				b, counts[b], tolerance*100, expected, lo, hi)
		}
	}
}
