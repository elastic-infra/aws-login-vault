package login

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type stubHTTPClient struct {
	status int
	body   string
	req    *http.Request
}

func (c *stubHTTPClient) Do(r *http.Request) (*http.Response, error) {
	c.req = r
	return &http.Response{
		StatusCode: c.status,
		Status:     http.StatusText(c.status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Request:    r,
	}, nil
}

func TestSessionExpiration(t *testing.T) {
	creds := aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret", SessionToken: "token"}

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
			hc := &stubHTTPClient{status: http.StatusOK, body: tt.body}
			cfg := aws.Config{
				Region:      "ap-northeast-1",
				HTTPClient:  hc,
				Credentials: aws.AnonymousCredentials{},
			}
			got, err := SessionExpiration(context.Background(), cfg, creds, "refresh-token")
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
			if hc.req == nil {
				t.Fatal("no request sent")
			}
			if auth := hc.req.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIDEXAMPLE/") {
				t.Errorf("request not signed with the given credentials: %q", auth)
			}
			if tok := hc.req.Header.Get("X-Amz-Security-Token"); tok != "token" {
				t.Errorf("X-Amz-Security-Token = %q, want %q", tok, "token")
			}
		})
	}
}
