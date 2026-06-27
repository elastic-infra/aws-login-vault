package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ExitCodeError carries a child process exit code so main can propagate it as
// the program's own exit status without printing an "Error:" prefix.
type ExitCodeError struct{ Code int }

func (e *ExitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// ecsCredentialOutput matches the ECS container credential provider protocol.
// Note the session token key is "Token" (not "SessionToken" as in
// credential_process).
type ecsCredentialOutput struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func newServerCmd(sf *storeFlags) *cobra.Command {
	opts := exportOptions{}
	cmd := &cobra.Command{
		Use:   "server [flags] [-- command [args...]]",
		Short: "Run a local ECS credential server (optionally exec a command with it)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(cmd.Context(), sf, opts, args)
		},
	}
	// Stop flag parsing at the first positional so the child command keeps its
	// own flags: `server --profile dev aws s3 ls --region x` passes --region to
	// the child. Server flags must precede the command.
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringVar(&opts.profile, "profile", defaultProfile, "profile name")
	cmd.Flags().StringVar(&opts.roleARN, "role", "", "role ARN to assume (enables AssumeRole mode)")
	cmd.Flags().StringVar(&opts.roleSessionName, "role-session-name", "", "RoleSessionName override (default: derived from sub)")
	cmd.Flags().StringVar(&opts.sourceIdentity, "source-identity", "", `SourceIdentity for AssumeRole. "auto" derives from sub; any other value is sent literally`)
	cmd.Flags().DurationVar(&opts.roleDuration, "role-duration", 0, "AssumeRole DurationSeconds (default 1h)")
	cmd.Flags().BoolVar(&opts.autoLogin, "auto-login", os.Getenv(envAutoLogin) == "1",
		"run login automatically if the profile is not authenticated (requires a local GUI session)")
	return cmd
}

func runServer(ctx context.Context, sf *storeFlags, opts exportOptions, args []string) error {
	store, err := openStore(sf)
	if err != nil {
		return err
	}

	// Warm up once so an unauthenticated profile fails here, before we start
	// the server (and before we spawn a child in exec mode).
	warm, err := resolveCredentials(ctx, store, opts)
	if err != nil {
		return err
	}
	_, _, _, _, region := warm.Creds()

	token, err := newAuthToken()
	if err != nil {
		return err
	}

	srv, err := newCredServer(ctx, token, func(ctx context.Context) (exportable, error) {
		return resolveCredentials(ctx, store, opts)
	})
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	if len(args) == 0 {
		return runServerBlocking(ctx, srv, opts.profile)
	}
	return runServerExec(srv, args, region)
}

func newAuthToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate auth token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// runServerBlocking prints the env the user must set and waits for a signal.
func runServerBlocking(ctx context.Context, srv *credServer, profile string) error {
	fmt.Fprintf(os.Stderr,
		"aws-login-vault credential server for profile %q on %s\n"+
			"Set these where your AWS tooling runs:\n\n"+
			"  export AWS_CONTAINER_CREDENTIALS_FULL_URI=%s\n"+
			"  export AWS_CONTAINER_AUTHORIZATION_TOKEN=%s\n\n"+
			"Press Ctrl-C to stop.\n",
		profile, srv.baseURL(), srv.baseURL(), srv.token)
	<-ctx.Done()
	return nil
}

// runServerExec sets the container env and runs args as a child process,
// forwarding signals so the child decides its own exit code (aws-vault's
// runSubProcess pattern; CommandContext's SIGKILL would clobber it).
func runServerExec(srv *credServer, args []string, region string) error {
	cmd := osexec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = buildChildEnv(os.Environ(), srv.baseURL(), srv.token, region)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %q: %w", args[0], err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	_ = cmd.Wait()
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return &ExitCodeError{Code: code}
	}
	return nil
}

// buildChildEnv strips static credential / profile env so the container
// provider wins, then injects the container endpoint and region (aws-vault's
// createEnv).
func buildChildEnv(base []string, fullURI, token, region string) []string {
	drop := map[string]bool{
		"AWS_ACCESS_KEY_ID":         true,
		"AWS_SECRET_ACCESS_KEY":     true,
		"AWS_SESSION_TOKEN":         true,
		"AWS_SECURITY_TOKEN":        true,
		"AWS_CREDENTIAL_EXPIRATION": true,
		"AWS_CREDENTIAL_FILE":       true,
		"AWS_PROFILE":               true,
		"AWS_DEFAULT_PROFILE":       true,
		"AWS_SDK_LOAD_CONFIG":       true,
	}
	env := make([]string, 0, len(base)+4)
	for _, kv := range base {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if drop[key] {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"AWS_CONTAINER_CREDENTIALS_FULL_URI="+fullURI,
		"AWS_CONTAINER_AUTHORIZATION_TOKEN="+token,
	)
	if region != "" {
		env = append(env,
			"AWS_REGION="+region,
			"AWS_DEFAULT_REGION="+region,
		)
	}
	return env
}

// credServer is a loopback ECS container credential server. Each request
// re-fetches credentials so the SDK transparently gets refreshed creds.
type credServer struct {
	listener net.Listener
	server   *http.Server
	token    string
	ctx      context.Context
	fetch    func(ctx context.Context) (exportable, error)
}

func newCredServer(ctx context.Context, token string, fetch func(context.Context) (exportable, error)) (*credServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cs := &credServer{
		listener: ln,
		token:    token,
		ctx:      ctx,
		fetch:    fetch,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", cs.handle)
	cs.server = &http.Server{Handler: mux}
	go func() { _ = cs.server.Serve(ln) }()
	return cs, nil
}

func (cs *credServer) baseURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/", cs.listener.Addr().(*net.TCPAddr).Port)
}

func (cs *credServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != cs.token {
		writeServerError(w, "invalid Authorization token", http.StatusForbidden)
		return
	}
	// Use the server's context, not r.Context(): a client timeout must not
	// abort an in-flight refresh.
	creds, err := cs.fetch(cs.ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: fetch credentials: %v\n", err)
		writeServerError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	akid, secret, sessionToken, expiration, _ := creds.Creds()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(ecsCredentialOutput{
		AccessKeyId:     akid,
		SecretAccessKey: secret,
		Token:           sessionToken,
		Expiration:      expiration.UTC().Format(time.RFC3339),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "server: encode response: %v\n", err)
	}
}

func writeServerError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"Message": msg})
}

// Close shuts the server down with a fresh timeout. The signal context is
// already cancelled by the time block mode returns, so it cannot be reused
// here or Shutdown would skip draining in-flight requests.
func (cs *credServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return cs.server.Shutdown(ctx)
}
