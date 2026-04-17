package login

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
)

const (
	verifierAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	verifierLength   = 64
)

// NewPKCE returns an RFC 7636 verifier/challenge pair.
// Uses rand.Int per index to avoid the modulo bias of byte%len(alphabet).
func NewPKCE() (verifier, challenge string, err error) {
	alphabetLen := big.NewInt(int64(len(verifierAlphabet)))
	var sb strings.Builder
	sb.Grow(verifierLength)
	for i := 0; i < verifierLength; i++ {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", "", err
		}
		sb.WriteByte(verifierAlphabet[n.Int64()])
	}
	verifier = sb.String()

	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
