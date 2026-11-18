package login

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/signin"
)

// SessionExpiration returns when the login session behind refreshToken ends,
// i.e. the refresh token's `exp`. Refreshing does not extend it.
// creds sign the request explicitly so the default chain (which may resolve
// back to this tool via credential_process) is never consulted.
func SessionExpiration(ctx context.Context, cfg aws.Config, creds aws.Credentials, refreshToken string) (time.Time, error) {
	client := signin.NewFromConfig(cfg, func(o *signin.Options) {
		o.Credentials = credentials.StaticCredentialsProvider{Value: creds}
	})
	out, err := client.IntrospectOAuth2TokenWithIAM(ctx, &signin.IntrospectOAuth2TokenWithIAMInput{
		Token:         aws.String(refreshToken),
		TokenTypeHint: aws.String("refresh_token"),
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("introspect refresh token: %w", err)
	}
	if !aws.ToBool(out.Active) {
		return time.Time{}, errors.New("introspect refresh token: token is not active")
	}
	if out.Exp == nil {
		return time.Time{}, errors.New("introspect refresh token: response missing exp")
	}
	return time.Unix(*out.Exp, 0), nil
}
