package login

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type dpopMiddleware struct {
	key *ecdsa.PrivateKey
}

func (m *dpopMiddleware) ID() string { return "DPoPInjector" }

func (m *dpopMiddleware) HandleFinalize(
	ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler,
) (middleware.FinalizeOutput, middleware.Metadata, error) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{},
			fmt.Errorf("dpop: unexpected transport type %T", in.Request)
	}
	proof, err := MakeDPoPProof(m.key, req.Method, req.URL.String())
	if err != nil {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("dpop: %w", err)
	}
	req.Header.Set("DPoP", proof)
	return next.HandleFinalize(ctx, in)
}

// WithDPoP registers a Finalize-step middleware that attaches a fresh DPoP
// proof to every CreateOAuth2Token request. Finalize runs after the HTTP
// request has been built, so Method and URL are stable when we sign.
func WithDPoP(key *ecdsa.PrivateKey) func(*signin.Options) {
	return func(o *signin.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Finalize.Add(&dpopMiddleware{key: key}, middleware.After)
		})
	}
}
