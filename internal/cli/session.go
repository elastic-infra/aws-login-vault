package cli

import (
	"github.com/hkobayash/aws-login-vault/internal/keychain"
	loginflow "github.com/hkobayash/aws-login-vault/internal/login"
)

func sessionFromLoginResult(r *loginflow.LoginResult) *keychain.Session {
	return &keychain.Session{
		SessionARN:      r.SessionARN,
		AccessKeyID:     r.AccessKeyID,
		SecretAccessKey: r.SecretAccessKey,
		SessionToken:    r.SessionToken,
		Expiration:      r.Expiration,
		RefreshToken:    r.RefreshToken,
		DPoPKeyPEM:      r.DPoPKeyPEM,
		Region:          r.Region,
		ClientID:        r.ClientID,
	}
}
