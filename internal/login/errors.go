package login

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/signin/types"
)

// TokenError classifies OAuth2 errors surfaced by /v1/token. Callers typically
// branch on the Code to decide whether to prompt re-login vs surface the raw
// server message.
type TokenError struct {
	Code    types.OAuth2ErrorCode
	Message string
	Cause   error
}

func (e *TokenError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return string(e.Code)
}

func (e *TokenError) Unwrap() error { return e.Cause }

// ClassifyTokenError extracts an OAuth2ErrorCode from a signin error.
// Returns the original error wrapped in *TokenError when recognised, or the
// original error untouched when the shape does not match.
func ClassifyTokenError(err error) error {
	if err == nil {
		return nil
	}
	var ade *types.AccessDeniedException
	if errors.As(err, &ade) {
		msg := ""
		if ade.Message != nil {
			msg = *ade.Message
		}
		return &TokenError{Code: ade.Error_, Message: msg, Cause: err}
	}
	var val *types.ValidationException
	if errors.As(err, &val) {
		msg := ""
		if val.Message != nil {
			msg = *val.Message
		}
		return &TokenError{Code: val.Error_, Message: msg, Cause: err}
	}
	return err
}

// IsReloginRequired reports whether the error indicates the user must run
// `login` again (refresh cannot recover).
func IsReloginRequired(err error) bool {
	var te *TokenError
	if !errors.As(err, &te) {
		return false
	}
	switch te.Code {
	case types.OAuth2ErrorCodeTokenExpired,
		types.OAuth2ErrorCodeUserCredentialsChanged,
		types.OAuth2ErrorCodeAuthcodeExpired:
		return true
	}
	return false
}
