package login

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

type dpopHeaderView struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"jwk"`
}

type dpopPayloadView struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

func TestMakeDPoPProof_StructureAndSignature(t *testing.T) {
	key, err := NewDPoPKey()
	if err != nil {
		t.Fatalf("NewDPoPKey: %v", err)
	}

	tests := []struct {
		name    string
		method  string
		rawURL  string
		wantHtm string
		wantHtu string
	}{
		{
			name:    "POST without query",
			method:  "POST",
			rawURL:  "https://us-east-1.signin.aws.amazon.com/v1/token",
			wantHtm: "POST",
			wantHtu: "https://us-east-1.signin.aws.amazon.com/v1/token",
		},
		{
			name:    "query is stripped from htu",
			method:  "POST",
			rawURL:  "https://example.com/path?foo=bar&baz=1",
			wantHtm: "POST",
			wantHtu: "https://example.com/path",
		},
		{
			name:    "fragment is stripped from htu",
			method:  "GET",
			rawURL:  "https://example.com/resource#top",
			wantHtm: "GET",
			wantHtu: "https://example.com/resource",
		},
		{
			name:    "lowercase method preserved",
			method:  "post",
			rawURL:  "https://example.com/token",
			wantHtm: "post",
			wantHtu: "https://example.com/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now().Unix()
			proof, err := MakeDPoPProof(key, tt.method, tt.rawURL)
			if err != nil {
				t.Fatalf("MakeDPoPProof: %v", err)
			}
			after := time.Now().Unix()

			parts := strings.Split(proof, ".")
			if len(parts) != 3 {
				t.Fatalf("proof has %d segments, want 3", len(parts))
			}

			hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Fatalf("decode header: %v", err)
			}
			var hdr dpopHeaderView
			if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
				t.Fatalf("parse header: %v", err)
			}
			if hdr.Typ != "dpop+jwt" {
				t.Errorf("typ = %q, want dpop+jwt", hdr.Typ)
			}
			if hdr.Alg != "ES256" {
				t.Errorf("alg = %q, want ES256", hdr.Alg)
			}
			if hdr.Jwk.Kty != "EC" || hdr.Jwk.Crv != "P-256" {
				t.Errorf("jwk kty=%s crv=%s, want EC/P-256", hdr.Jwk.Kty, hdr.Jwk.Crv)
			}
			assertBase64URLLen(t, "jwk.x", hdr.Jwk.X, 32)
			assertBase64URLLen(t, "jwk.y", hdr.Jwk.Y, 32)

			plBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			var pl dpopPayloadView
			if err := json.Unmarshal(plBytes, &pl); err != nil {
				t.Fatalf("parse payload: %v", err)
			}
			if pl.Htm != tt.wantHtm {
				t.Errorf("htm = %q, want %q", pl.Htm, tt.wantHtm)
			}
			if pl.Htu != tt.wantHtu {
				t.Errorf("htu = %q, want %q", pl.Htu, tt.wantHtu)
			}
			if pl.Iat < before || pl.Iat > after {
				t.Errorf("iat = %d not in [%d, %d]", pl.Iat, before, after)
			}
			if len(pl.Jti) == 0 {
				t.Error("jti is empty")
			}

			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			if len(sig) != 64 {
				t.Fatalf("sig length = %d, want 64 (r||s, 32 bytes each)", len(sig))
			}
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			signingInput := parts[0] + "." + parts[1]
			digest := sha256.Sum256([]byte(signingInput))
			if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
				t.Error("ECDSA verification failed")
			}
		})
	}
}

func TestMakeDPoPProof_UniqueJTIPerCall(t *testing.T) {
	key, _ := NewDPoPKey()
	seen := make(map[string]struct{})
	for i := 0; i < 16; i++ {
		proof, err := MakeDPoPProof(key, "POST", "https://example.com/token")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(proof, ".")
		plBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var pl dpopPayloadView
		_ = json.Unmarshal(plBytes, &pl)
		if _, dup := seen[pl.Jti]; dup {
			t.Fatalf("duplicate jti at iter %d: %s", i, pl.Jti)
		}
		seen[pl.Jti] = struct{}{}
	}
}

func TestMakeDPoPProof_InvalidURL(t *testing.T) {
	key, _ := NewDPoPKey()
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"parseable opaque", "mailto:foo@example.com", false}, // url.Parse accepts this
		{"bare host", "https://example.com", false},
		{"control character", "http://\x7f/x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MakeDPoPProof(key, "POST", tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func assertBase64URLLen(t *testing.T, name, encoded string, wantBytes int) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("%s: decode: %v", name, err)
	}
	if len(b) != wantBytes {
		t.Errorf("%s: decoded length = %d, want %d", name, len(b), wantBytes)
	}
}
