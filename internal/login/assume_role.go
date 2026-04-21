package login

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	DefaultAssumeRoleDuration = 1 * time.Hour
	AssumedExpiryWindow       = 5 * time.Minute
)

// BaseSession bundles the login_session values AssumeRole needs: the
// credentials to sign the STS call, and the sub ARN used to derive a default
// RoleSessionName / SourceIdentity.
type BaseSession struct {
	Credentials aws.Credentials
	SessionARN  string
}

type AssumeRoleInput struct {
	Config          aws.Config // Region / HTTP defaults; Credentials are ignored (Base is used).
	Base            BaseSession
	RoleARN         string
	RoleSessionName string        // empty → derived from Base.SessionARN
	SourceIdentity  string        // empty → SetSourceIdentity not sent
	Duration        time.Duration // zero → DefaultAssumeRoleDuration
}

type AssumeRoleOutput struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	RoleSessionName string
	SourceIdentity  string
}

func AssumeRole(ctx context.Context, in AssumeRoleInput) (*AssumeRoleOutput, error) {
	if in.RoleARN == "" {
		return nil, errors.New("role arn is required")
	}

	sessionName := in.RoleSessionName
	if sessionName == "" {
		sessionName = DeriveRoleSessionName(in.Base.SessionARN)
	}
	if sessionName == "" {
		return nil, fmt.Errorf("could not derive a role session name from %q; specify --role-session-name", in.Base.SessionARN)
	}

	duration := in.Duration
	if duration == 0 {
		duration = DefaultAssumeRoleDuration
	}

	cfg := in.Config.Copy()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(
		in.Base.Credentials.AccessKeyID,
		in.Base.Credentials.SecretAccessKey,
		in.Base.Credentials.SessionToken,
	)

	client := sts.NewFromConfig(cfg)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(in.RoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(int32(duration.Seconds())),
	}
	if in.SourceIdentity != "" {
		input.SourceIdentity = aws.String(in.SourceIdentity)
	}

	resp, err := client.AssumeRole(ctx, input)
	if err != nil {
		return nil, err
	}
	if resp.Credentials == nil {
		return nil, errors.New("assume_role: missing credentials in response")
	}

	return &AssumeRoleOutput{
		AccessKeyID:     aws.ToString(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(resp.Credentials.SessionToken),
		Expiration:      aws.ToTime(resp.Credentials.Expiration),
		RoleSessionName: sessionName,
		SourceIdentity:  in.SourceIdentity,
	}, nil
}

var roleSessionSanitize = regexp.MustCompile(`[^\w+=,.@\-]`)

// DeriveRoleSessionName extracts an IAM-compatible session name from a sub ARN.
// Returns empty string if the ARN shape is unknown. Callers should fall back
// to an explicit --role-session-name.
//
//   - arn:aws:iam::ACCT:user/NAME                  → NAME
//   - arn:aws:sts::ACCT:assumed-role/ROLE/SESSION  → SESSION
//   - arn:aws:sts::ACCT:federated-user/NAME        → NAME
func DeriveRoleSessionName(subARN string) string {
	idx := strings.LastIndex(subARN, ":")
	if idx < 0 || idx == len(subARN)-1 {
		return ""
	}
	resource := subARN[idx+1:]
	switch {
	case strings.HasPrefix(resource, "user/"):
		return sanitizeSessionName(resource[len("user/"):])
	case strings.HasPrefix(resource, "assumed-role/"):
		parts := strings.SplitN(resource[len("assumed-role/"):], "/", 2)
		if len(parts) != 2 {
			return ""
		}
		return sanitizeSessionName(parts[1])
	case strings.HasPrefix(resource, "federated-user/"):
		return sanitizeSessionName(resource[len("federated-user/"):])
	default:
		return ""
	}
}

func sanitizeSessionName(name string) string {
	s := roleSessionSanitize.ReplaceAllString(name, "_")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
