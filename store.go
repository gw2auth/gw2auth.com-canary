package main

import "context"

type RefreshTokenStore interface {
	Load(ctx context.Context) (string, error)
	Store(ctx context.Context, token string) error
}
