package login

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

type callbackResult struct {
	code  string
	state string
	err   error
}

type CallbackServer struct {
	listener net.Listener
	server   *http.Server
	result   chan callbackResult
}

func NewCallbackServer() (*CallbackServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cs := &CallbackServer{
		listener: ln,
		result:   make(chan callbackResult, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", cs.handle)
	cs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() { _ = cs.server.Serve(ln) }()
	return cs, nil
}

func (cs *CallbackServer) RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/oauth/callback",
		cs.listener.Addr().(*net.TCPAddr).Port)
}

func (cs *CallbackServer) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var res callbackResult
	if errStr := q.Get("error"); errStr != "" {
		desc := q.Get("error_description")
		if desc != "" {
			res = callbackResult{err: fmt.Errorf("authorization failed: %s: %s", errStr, desc)}
		} else {
			res = callbackResult{err: fmt.Errorf("authorization failed: %s", errStr)}
		}
	} else {
		res = callbackResult{code: q.Get("code"), state: q.Get("state")}
	}
	select {
	case cs.result <- res:
	default:
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if res.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, failureHTML)
		return
	}
	fmt.Fprint(w, successHTML)
}

// Wait blocks until the browser hits the callback, the user cancels, or the
// provided context is done. A 10-minute safety cap protects against a browser
// that never returns.
func (cs *CallbackServer) Wait(ctx context.Context) (code, state string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	select {
	case r := <-cs.result:
		return r.code, r.state, r.err
	case <-ctx.Done():
		return "", "", errors.New("timed out waiting for browser callback")
	}
}

func (cs *CallbackServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return cs.server.Shutdown(ctx)
}

const successHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Login successful</title></head><body>
<h1>Login successful</h1>
<p>You can close this window and return to the terminal.</p>
</body></html>`

const failureHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Login failed</title></head><body>
<h1>Login failed</h1>
<p>Return to the terminal for details.</p>
</body></html>`
