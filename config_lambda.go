//go:build lambda

package main

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/gw2auth/gw2auth.com-canary/oauth2"
	"golang.org/x/sync/errgroup"
	"net/http"
	"strings"
	"sync"
)

const (
	ssmParamClientId     = "/canary/gw2auth/client-id"
	ssmParamClientSecret = "/canary/gw2auth/client-secret"
	ssmParamRefreshToken = "/canary/gw2auth/refresh-token"
	ssmParamApiKey       = "/canary/api-key"
)

var awsConfig = sync.OnceValues(func() (aws.Config, error) {
	return config.LoadDefaultConfig(context.Background())
})

var ssmClient = sync.OnceValues(func() (*ssm.Client, error) {
	cfg, err := awsConfig()
	if err != nil {
		return nil, err
	}

	return ssm.NewFromConfig(cfg), nil
})

type lambdaRefreshTokenStore struct {
	ssm *ssm.Client
}

func (rts *lambdaRefreshTokenStore) Load(ctx context.Context) (string, error) {
	resp, err := rts.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(ssmParamRefreshToken),
		WithDecryption: aws.Bool(true),
	})

	if err != nil {
		return "", err
	}

	return *resp.Parameter.Value, nil
}

func (rts *lambdaRefreshTokenStore) Store(ctx context.Context, token string) error {
	_, err := rts.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(ssmParamRefreshToken),
		Value:     aws.String(token),
		Type:      types.ParameterTypeSecureString,
		Overwrite: aws.Bool(true),
	})

	return err
}

func oauth2Client(ctx context.Context) (*oauth2.Client, error) {
	var clientId string
	var clientSecret string
	var md oauth2.ServerMetadata

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		ssmc, err := ssmClient()
		if err != nil {
			return err
		}

		resp, err := ssmc.GetParameters(ctx, &ssm.GetParametersInput{
			Names: []string{
				ssmParamClientId,
				ssmParamClientSecret,
			},
			WithDecryption: aws.Bool(true),
		})

		if err != nil {
			return err
		}

		for _, param := range resp.Parameters {
			switch *param.Name {
			case ssmParamClientId:
				clientId = *param.Value

			case ssmParamClientSecret:
				clientSecret = *param.Value
			}
		}

		if clientId == "" || clientSecret == "" {
			return errors.New("no issuer or client id or client secret found")
		}

		return nil
	})

	g.Go(func() error {
		var err error
		md, err = oauth2.LoadMetadataFromOAuthIssuer(ctx, "https://gw2auth.com")
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return oauth2.NewClient(clientId, clientSecret, md), nil
}

func refreshTokenStore() (RefreshTokenStore, error) {
	ssmc, err := ssmClient()
	if err != nil {
		return nil, err
	}

	return &lambdaRefreshTokenStore{ssmc}, nil
}

func applyMiddleware(ctx context.Context, handler http.Handler) (http.Handler, error) {
	var apiKey string
	{
		ssmc, err := ssmClient()
		if err != nil {
			return nil, err
		}

		resp, err := ssmc.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(ssmParamApiKey),
			WithDecryption: aws.Bool(true),
		})

		if err != nil {
			return nil, err
		}

		apiKey = *resp.Parameter.Value
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != apiKey {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r)
	}), nil
}
