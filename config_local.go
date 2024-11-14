//go:build !lambda

package main

import (
	"context"
	"fmt"
	"github.com/gw2auth/gw2auth.com-canary/oauth2"
	"net/http"
	"os"
)

type localRefreshTokenStore struct{}

func (localRefreshTokenStore) Load(ctx context.Context) (string, error) {
	return os.Getenv("REFRESH_TOKEN"), nil
}

func (localRefreshTokenStore) Store(ctx context.Context, token string) error {
	fmt.Printf("refresh_token: %s\n", token)
	return nil
}

func oauth2Client(ctx context.Context) (*oauth2.Client, error) {
	clientId := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	md, err := oauth2.LoadMetadataFromOAuthIssuer(ctx, "https://gw2auth.com")
	if err != nil {
		return nil, err
	}

	return oauth2.NewClient(clientId, clientSecret, md), nil
}

func refreshTokenStore() (RefreshTokenStore, error) {
	return localRefreshTokenStore{}, nil
}

func applyMiddleware(ctx context.Context, handler http.Handler) (http.Handler, error) {
	return handler, nil
}
