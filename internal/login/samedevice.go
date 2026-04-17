package login

import (
	"context"
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
// open the browser, wait for redirect, exchange the auth code for tokens.
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
	authURL := buildAuthorizeURL(baseURL, state, challenge, cb.RedirectURI())

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

	client := signin.NewFromConfig(cfg, WithDPoP(key))
	out, err := client.CreateOAuth2Token(ctx, &signin.CreateOAuth2TokenInput{
		TokenInput: &types.CreateOAuth2TokenRequestBody{
			ClientId:     aws.String(SameDeviceClientID),
			GrantType:    aws.String("authorization_code"),
			Code:         aws.String(code),
			CodeVerifier: aws.String(verifier),
			RedirectUri:  aws.String(cb.RedirectURI()),
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

	return &LoginResult{
		AccessKeyID:     aws.ToString(out.TokenOutput.AccessToken.AccessKeyId),
		SecretAccessKey: aws.ToString(out.TokenOutput.AccessToken.SecretAccessKey),
		SessionToken:    aws.ToString(out.TokenOutput.AccessToken.SessionToken),
		Expiration:      time.Now().Add(time.Duration(aws.ToInt32(out.TokenOutput.ExpiresIn)) * time.Second),
		RefreshToken:    aws.ToString(out.TokenOutput.RefreshToken),
		DPoPKeyPEM:      pemStr,
		SessionARN:      sessionARN,
		Region:          cfg.Region,
		ClientID:        SameDeviceClientID,
	}, nil
}

func buildAuthorizeURL(baseURL, state, challenge, redirectURI string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", SameDeviceClientID)
	q.Set("state", state)
	// AWS uses the non-standard "SHA-256" label instead of RFC 7636's "S256".
	q.Set("code_challenge_method", "SHA-256")
	q.Set("scope", "openid")
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", challenge)
	return baseURL + "/v1/authorize?" + q.Encode()
}
