package login

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type dpopHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Jwk jwk    `json:"jwk"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dpopPayload struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

func NewDPoPKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MakeDPoPProof builds a DPoP JWT for a single request.
// htu drops query and fragment per RFC 9449 §4.2.
func MakeDPoPProof(key *ecdsa.PrivateKey, method, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.RawQuery = ""
	u.Fragment = ""

	hdr := dpopHeader{
		Typ: "dpop+jwt",
		Alg: "ES256",
		Jwk: jwk{
			Kty: "EC",
			Crv: "P-256",
			X:   ecCoordinate(key.PublicKey.X),
			Y:   ecCoordinate(key.PublicKey.Y),
		},
	}
	pl := dpopPayload{
		Htm: method,
		Htu: u.String(),
		Iat: time.Now().Unix(),
		Jti: uuid.NewString(),
	}

	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	plJSON, err := json.Marshal(pl)
	if err != nil {
		return "", err
	}
	signingInput := fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(hdrJSON),
		base64.RawURLEncoding.EncodeToString(plJSON),
	)

	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}

	// ES256 signature is r||s, each fixed 32 bytes.
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ecCoordinate encodes a P-256 coordinate as 32-byte left-zero-padded base64url.
func ecCoordinate(b *big.Int) string {
	buf := make([]byte, 32)
	src := b.Bytes()
	copy(buf[32-len(src):], src)
	return base64.RawURLEncoding.EncodeToString(buf)
}
