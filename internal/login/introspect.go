package login

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/signin"
)

// LookupSessionExpiration returns when the login session behind r ends, i.e.
// its refresh token's `exp`. Refreshing does not extend it.
// r's credentials sign the request explicitly so the default chain (which may
// resolve back to this tool via credential_process) is never consulted.
func LookupSessionExpiration(ctx context.Context, cfg aws.Config, r *LoginResult) (time.Time, error) {
	client := signin.NewFromConfig(cfg, func(o *signin.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(r.AccessKeyID, r.SecretAccessKey, r.SessionToken)
		o.RetryMaxAttempts = 1
	})
	out, err := client.IntrospectOAuth2TokenWithIAM(ctx, &signin.IntrospectOAuth2TokenWithIAMInput{
		Token:         aws.String(r.RefreshToken),
		TokenTypeHint: aws.String("refresh_token"),
	})
	if err != nil {
		return time.Time{}, err
	}
	if !aws.ToBool(out.Active) {
		return time.Time{}, errors.New("refresh token is not active")
	}
	if out.Exp == nil {
		return time.Time{}, errors.New("response missing exp")
	}
	return time.Unix(*out.Exp, 0), nil
}
