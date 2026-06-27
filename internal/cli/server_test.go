package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeCreds is a stub exportable for handler tests.
type fakeCreds struct {
	akid, secret, token, region string
	exp                         time.Time
}

func (f fakeCreds) Creds() (akid, secret, token string, expiration time.Time, region string) {
	return f.akid, f.secret, f.token, f.exp, f.region
}

func newTestServer(token string, fetch func(context.Context) (exportable, error)) *credServer {
	return &credServer{token: token, ctx: context.Background(), fetch: fetch}
}

func TestCredServerHandle(t *testing.T) {
	exp := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	okFetch := func(context.Context) (exportable, error) {
		return fakeCreds{akid: "ASIA123", secret: "sekret", token: "tok", region: "us-east-1", exp: exp}, nil
	}
	errFetch := func(context.Context) (exportable, error) {
		return nil, errors.New("boom")
	}

	tests := []struct {
		name       string
		token      string
		authHeader string
		fetch      func(context.Context) (exportable, error)
		wantStatus int
	}{
		{"authorized", "secret", "secret", okFetch, http.StatusOK},
		{"wrong token", "secret", "nope", okFetch, http.StatusForbidden},
		{"missing token", "secret", "", okFetch, http.StatusForbidden},
		{"fetch error", "secret", "secret", errFetch, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := newTestServer(tt.token, tt.fetch)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			cs.handle(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			switch tt.wantStatus {
			case http.StatusOK:
				var out ecsCredentialOutput
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if out.Token != "tok" {
					t.Errorf("Token = %q, want %q", out.Token, "tok")
				}
				if out.AccessKeyId != "ASIA123" || out.SecretAccessKey != "sekret" {
					t.Errorf("creds mismatch: %+v", out)
				}
				if out.Expiration != "2026-06-27T12:00:00Z" {
					t.Errorf("Expiration = %q, want RFC3339 UTC", out.Expiration)
				}
			case http.StatusForbidden, http.StatusInternalServerError:
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode error body: %v", err)
				}
				if _, ok := body["Message"]; !ok {
					t.Errorf("error body missing %q key: %v", "Message", body)
				}
			}
		})
	}
}

func TestBuildChildEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"AWS_ACCESS_KEY_ID=AKIA",
		"AWS_SECRET_ACCESS_KEY=secret",
		"AWS_SESSION_TOKEN=tok",
		"AWS_PROFILE=dev",
		"AWS_DEFAULT_PROFILE=dev",
		"AWS_SDK_LOAD_CONFIG=1",
		"HOME=/home/u",
	}

	t.Run("with region", func(t *testing.T) {
		env := buildChildEnv(base, "http://127.0.0.1:9/", "tkn", "ap-northeast-1")

		mustHave := []string{
			"PATH=/usr/bin",
			"HOME=/home/u",
			"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:9/",
			"AWS_CONTAINER_AUTHORIZATION_TOKEN=tkn",
			"AWS_REGION=ap-northeast-1",
			"AWS_DEFAULT_REGION=ap-northeast-1",
		}
		for _, want := range mustHave {
			if !slices.Contains(env, want) {
				t.Errorf("env missing %q", want)
			}
		}
		for _, kv := range env {
			for _, dropped := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SDK_LOAD_CONFIG"} {
				if strings.HasPrefix(kv, dropped+"=") {
					t.Errorf("static credential env not dropped: %q", kv)
				}
			}
		}
	})

	t.Run("without region", func(t *testing.T) {
		env := buildChildEnv(base, "http://127.0.0.1:9/", "tkn", "")
		for _, kv := range env {
			if strings.HasPrefix(kv, "AWS_REGION=") || strings.HasPrefix(kv, "AWS_DEFAULT_REGION=") {
				t.Errorf("region env set despite empty region: %q", kv)
			}
		}
	})
}
