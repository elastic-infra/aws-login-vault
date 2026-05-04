package login

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/aws-sdk-go-v2/service/signin/types"
)

// Refresh exchanges a refresh token for a new short-lived credential set.
// The same DPoP key must be reused (cnf.jkt binding), and the previous
// SessionARN/Region are carried through since the refresh response does not
// echo the ID token.
func Refresh(ctx context.Context, cfg aws.Config, prev *LoginResult) (*LoginResult, error) {
	if prev == nil {
		return nil, errors.New("refresh: previous result is nil")
	}
	key, err := ParseECPrivateKeyPEM(prev.DPoPKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse dpop key: %w", err)
	}
	client := signin.NewFromConfig(cfg, WithDPoP(key))
	out, err := client.CreateOAuth2Token(ctx, &signin.CreateOAuth2TokenInput{
		TokenInput: &types.CreateOAuth2TokenRequestBody{
			ClientId:     aws.String(prev.ClientID),
			GrantType:    aws.String("refresh_token"),
			RefreshToken: aws.String(prev.RefreshToken),
		},
	})
	if err != nil {
		return nil, ClassifyTokenError(err)
	}
	if out.TokenOutput == nil || out.TokenOutput.AccessToken == nil {
		return nil, errors.New("refresh response missing AccessToken")
	}

	r := &LoginResult{
		DPoPKeyPEM: prev.DPoPKeyPEM,
		SessionARN: prev.SessionARN,
		Region:     prev.Region,
		ClientID:   prev.ClientID,
	}
	applyTokenResponse(r, out.TokenOutput)
	return r, nil
}
