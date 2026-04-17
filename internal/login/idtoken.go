package login

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ExtractSubFromIDToken pulls the `sub` claim from an unsigned JWT payload.
// The ID token signature is not verified here; trust flows from the TLS+DPoP
// channel that produced the token.
func ExtractSubFromIDToken(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		s := parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4)
		payload, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	var p struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", err
	}
	if p.Sub == "" {
		return "", errors.New("id_token missing sub claim")
	}
	return p.Sub, nil
}
