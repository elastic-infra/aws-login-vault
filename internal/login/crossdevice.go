package login

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
)

const CrossDeviceClientID = "arn:aws:signin:::devtools/cross-device"

// VerificationCodeReader returns the base64 string the user pasted from the
// browser after CROSS_DEVICE authentication. Implemented by the CLI as a
// stdin prompt; tests can inject a static string instead.
type VerificationCodeReader func() (string, error)

// CrossDeviceLogin drives the CROSS_DEVICE flow: print the authorize URL,
// wait for the user to paste the base64 verification code, and exchange the
// extracted auth code for tokens. Used when the local machine cannot bind a
// callback URL the browser can reach (e.g. SSH'd into a remote dev box).
func CrossDeviceLogin(ctx context.Context, cfg aws.Config, read VerificationCodeReader) (*LoginResult, error) {
	if cfg.Region == "" {
		return nil, errors.New("region is required for login")
	}
	if read == nil {
		return nil, errors.New("verification code reader is required")
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

	baseURL, err := SigninBaseURL(cfg.Region)
	if err != nil {
		return nil, err
	}
	redirectURI := baseURL + "/v1/sessions/confirmation"
	authURL := buildAuthorizeURL(baseURL, CrossDeviceClientID, state, challenge, redirectURI)

	fmt.Fprintln(os.Stderr, "Open this URL in a browser on your local machine:")
	fmt.Fprintf(os.Stderr, "  %s\n\n", authURL)
	fmt.Fprintln(os.Stderr, "After authentication, paste the verification code shown in the browser.")

	raw, err := read()
	if err != nil {
		return nil, fmt.Errorf("read verification code: %w", err)
	}
	code, gotState, err := parseVerificationCode(raw)
	if err != nil {
		return nil, err
	}
	if gotState != state {
		return nil, errors.New("state mismatch in verification code")
	}

	return exchangeAuthCode(ctx, cfg, key, CrossDeviceClientID, code, verifier, redirectURI)
}

// parseVerificationCode decodes the base64 string the user pastes and pulls
// out the (code, state) pair. Accepts both standard and URL-safe base64,
// with or without padding.
func parseVerificationCode(s string) (code, state string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("verification code is empty")
	}

	decoded, err := decodeBase64Permissive(s)
	if err != nil {
		return "", "", fmt.Errorf("decode verification code: %w", err)
	}

	values, err := url.ParseQuery(string(decoded))
	if err != nil {
		return "", "", fmt.Errorf("parse verification code: %w", err)
	}
	code = values.Get("code")
	state = values.Get("state")
	if code == "" || state == "" {
		return "", "", errors.New("verification code missing state or code")
	}
	return code, state, nil
}

// decodeBase64Permissive tries each base64 variant the AWS Sign-In response
// might emit (Std / URL-safe, with or without padding) and returns the first
// successful decode.
func decodeBase64Permissive(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not a valid base64 string")
}
