package login

import (
	"errors"
	"fmt"
	"strings"
)

// SigninBaseURL returns the browser-facing authorize endpoint base for a region.
// The SDK resolves /v1/token on its own; this is only for the URL we hand to the
// browser (the SDK never sees /v1/authorize).
func SigninBaseURL(region string) (string, error) {
	if region == "" {
		return "", errors.New("region is required")
	}
	switch partitionForRegion(region) {
	case "aws":
		return fmt.Sprintf("https://%s.signin.aws.amazon.com", region), nil
	case "aws-cn":
		return fmt.Sprintf("https://%s.signin.amazonaws.cn", region), nil
	case "aws-us-gov":
		return fmt.Sprintf("https://%s.signin.amazonaws-us-gov.com", region), nil
	default:
		return "", fmt.Errorf("unsupported partition for region: %s", region)
	}
}

func partitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}
