package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/gw2auth/gw2auth.com-canary/oauth2"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c, err := oauth2Client(ctx)
	if err != nil {
		panic(err)
	}

	rts, err := refreshTokenStore()
	if err != nil {
		panic(err)
	}

	handler, err := applyMiddleware(ctx, buildHandler(c, rts))
	if err != nil {
		panic(err)
	}

	if err = runServer(ctx, handler); err != nil {
		panic(err)
	}
}

func buildHandler(c *oauth2.Client, rts RefreshTokenStore) http.Handler {
	var mtx sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mtx.Lock()
		defer mtx.Unlock()

		ctx := r.Context()
		tk, err := rts.Load(ctx)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		resp, err := c.RefreshToken(ctx, tk)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to refresh: %v", err), http.StatusBadGateway)
			return
		}

		if err = rts.Store(ctx, resp.RefreshToken); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func runServer(ctx context.Context, handler http.Handler) error {
	srv := http.Server{
		Addr:    ":8080",
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	done := make(chan error)
	closeCtx, closeCancel := context.WithCancel(ctx)
	defer closeCancel()

	go func() {
		defer close(done)
		<-closeCtx.Done()
		done <- srv.Shutdown(ctx)
	}()

	err := func() error {
		defer closeCancel()

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}()

	return errors.Join(err, <-done)
}
