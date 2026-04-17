package awsconfig

import (
	"context"
	"errors"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// ResolveRegion follows the usual AWS precedence: explicit flag, then env,
// then the named profile's region in ~/.aws/config. An empty result is an
// error: region is mandatory for the signin endpoint.
func ResolveRegion(ctx context.Context, profile, flagRegion string) (string, error) {
	if flagRegion != "" {
		return flagRegion, nil
	}
	if r := os.Getenv("AWS_REGION"); r != "" {
		return r, nil
	}
	if r := os.Getenv("AWS_DEFAULT_REGION"); r != "" {
		return r, nil
	}
	opts := []func(*config.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err == nil && cfg.Region != "" {
		return cfg.Region, nil
	}
	return "", errors.New("region not specified; use --region or set AWS_REGION")
}

// NewAWSConfig builds the aws.Config used for the signin client. The signin
// CreateOAuth2Token operation resolves to Anonymous auth, so credentials are
// not required; only the region matters.
func NewAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}
