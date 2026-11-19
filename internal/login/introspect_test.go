package login

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestLookupSessionExpiration(t *testing.T) {
	r := &LoginResult{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "secret",
		SessionToken:    "token",
		RefreshToken:    "refresh-token",
	}

	tests := []struct {
		name    string
		body    string
		want    time.Time
		wantErr string
	}{
		{
			name: "active",
			body: `{"active":true,"exp":1795021245,"iat":1795003776,"token_type":"refresh_token"}`,
			want: time.Unix(1795021245, 0),
		},
		{
			name:    "inactive",
			body:    `{"active":false}`,
			wantErr: "not active",
		},
		{
			name:    "missing exp",
			body:    `{"active":true}`,
			wantErr: "missing exp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			cfg := aws.Config{
				Region:      "ap-northeast-1",
				Credentials: aws.AnonymousCredentials{},
				HTTPClient: smithyhttp.ClientDoFunc(func(rq *http.Request) (*http.Response, error) {
					req = rq
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(tt.body)),
						Request:    rq,
					}, nil
				}),
			}
			got, err := LookupSessionExpiration(context.Background(), cfg, r)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			if req == nil {
				t.Fatal("no request sent")
			}
			if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIDEXAMPLE/") {
				t.Errorf("request not signed with the given credentials: %q", auth)
			}
			if tok := req.Header.Get("X-Amz-Security-Token"); tok != "token" {
				t.Errorf("X-Amz-Security-Token = %q, want %q", tok, "token")
			}
		})
	}
}

func TestSetSessionExpiration(t *testing.T) {
	base := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	credsExp := base.Add(15 * time.Minute)

	tests := []struct {
		name    string
		end     time.Time
		wantExp time.Time
	}{
		{"unknown end keeps expiration", time.Time{}, credsExp},
		{"end after credentials", base.Add(time.Hour), credsExp},
		{"end before credentials caps them", base.Add(5 * time.Minute), base.Add(5 * time.Minute)},
		{"end equal to credentials", credsExp, credsExp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &LoginResult{Expiration: credsExp}
			r.SetSessionExpiration(tt.end)
			if !r.Expiration.Equal(tt.wantExp) {
				t.Errorf("Expiration = %v, want %v", r.Expiration, tt.wantExp)
			}
			if !r.SessionExpiration.Equal(tt.end) {
				t.Errorf("SessionExpiration = %v, want %v", r.SessionExpiration, tt.end)
			}
		})
	}
}
