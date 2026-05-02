package login

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/aws-sdk-go-v2/service/signin/types"
	"github.com/google/uuid"
	"github.com/pkg/browser"
)

const SameDeviceClientID = "arn:aws:signin:::devtools/same-device"

type LoginResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	RefreshToken    string
	DPoPKeyPEM      string
	SessionARN      string
	Region          string
	ClientID        string
}

// SameDeviceLogin drives the full SAME_DEVICE OAuth2 + PKCE + DPoP flow:
// open the browser, wait for redirect on a local callback server, exchange
// the auth code for tokens.
func SameDeviceLogin(ctx context.Context, cfg aws.Config) (*LoginResult, error) {
	if cfg.Region == "" {
		return nil, errors.New("region is required for login")
	}

	verifier, challenge, err := NewPKCE()
	if err != nil {
		return nil, fmt.Errorf("pkce: %w", err)
	}
	state := uuid.NewString()
	key, err := NewDPoPKey()
	if err != nil {
		return nil, fmt.Errorf("dpop key: %w", err)
	}

	cb, err := NewCallbackServer()
	if err != nil {
		return nil, fmt.Errorf("callback server: %w", err)
	}
	defer func() { _ = cb.Close() }()

	baseURL, err := SigninBaseURL(cfg.Region)
	if err != nil {
		return nil, err
	}
	authURL := buildAuthorizeURL(baseURL, SameDeviceClientID, state, challenge, cb.RedirectURI())

	fmt.Fprintln(os.Stderr, "Opening browser for AWS sign-in...")
	fmt.Fprintf(os.Stderr, "If the browser does not open, visit:\n  %s\n", authURL)
	_ = browser.OpenURL(authURL)

	code, gotState, err := cb.Wait(ctx)
	if err != nil {
		return nil, err
	}
	if gotState != state {
		return nil, errors.New("state mismatch in callback")
	}

	return exchangeAuthCode(ctx, cfg, key, SameDeviceClientID, code, verifier, cb.RedirectURI())
}

// buildAuthorizeURL composes the /v1/authorize URL for a given client_id and
// redirect_uri. Used by both SAME_DEVICE and CROSS_DEVICE flows; only the
// pair of (client_id, redirect_uri) differs between them.
func buildAuthorizeURL(baseURL, clientID, state, challenge, redirectURI string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("state", state)
	// AWS uses the non-standard "SHA-256" label instead of RFC 7636's "S256".
	q.Set("code_challenge_method", "SHA-256")
	q.Set("scope", "openid")
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	return baseURL + "/v1/authorize?" + q.Encode()
}

// exchangeAuthCode posts to /v1/token with grant_type=authorization_code and
// builds a LoginResult from the response. The DPoP key, client_id, and
// redirect_uri must be the same values that were used at /v1/authorize.
func exchangeAuthCode(
	ctx context.Context, cfg aws.Config, key *ecdsa.PrivateKey,
	clientID, code, verifier, redirectURI string,
) (*LoginResult, error) {
	client := signin.NewFromConfig(cfg, WithDPoP(key))
	out, err := client.CreateOAuth2Token(ctx, &signin.CreateOAuth2TokenInput{
		TokenInput: &types.CreateOAuth2TokenRequestBody{
			ClientId:     aws.String(clientID),
			GrantType:    aws.String("authorization_code"),
			Code:         aws.String(code),
			CodeVerifier: aws.String(verifier),
			RedirectUri:  aws.String(redirectURI),
		},
	})
	if err != nil {
		return nil, ClassifyTokenError(err)
	}
	if out.TokenOutput == nil || out.TokenOutput.AccessToken == nil {
		return nil, errors.New("token response missing AccessToken")
	}
	if out.TokenOutput.IdToken == nil {
		return nil, errors.New("authorization_code response missing IdToken")
	}

	sessionARN, err := ExtractSubFromIDToken(*out.TokenOutput.IdToken)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}

	pemStr, err := SerializeECPrivateKeyPEM(key)
	if err != nil {
		return nil, fmt.Errorf("serialize dpop key: %w", err)
	}

	r := &LoginResult{
		DPoPKeyPEM: pemStr,
		SessionARN: sessionARN,
		Region:     cfg.Region,
		ClientID:   clientID,
	}
	applyTokenResponse(r, out.TokenOutput)
	return r, nil
}

// applyTokenResponse copies short-lived credential fields from a /v1/token
// response into r. The caller fills in flow-specific fields (DPoPKeyPEM,
// SessionARN, Region, ClientID) before calling this.
func applyTokenResponse(r *LoginResult, out *types.CreateOAuth2TokenResponseBody) {
	r.AccessKeyID = aws.ToString(out.AccessToken.AccessKeyId)
	r.SecretAccessKey = aws.ToString(out.AccessToken.SecretAccessKey)
	r.SessionToken = aws.ToString(out.AccessToken.SessionToken)
	r.Expiration = time.Now().Add(time.Duration(aws.ToInt32(out.ExpiresIn)) * time.Second)
	r.RefreshToken = aws.ToString(out.RefreshToken)
}
