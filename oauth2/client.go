package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Client struct {
	httpClient   *http.Client
	clientId     string
	clientSecret string
	metadata     ServerMetadata
}

type ClientOption interface {
	Apply(c *Client)
}

type WithHttpClient http.Client

func (opt *WithHttpClient) Apply(c *Client) {
	c.httpClient = (*http.Client)(opt)
}

func NewClient(clientId, clientSecret string, metadata ServerMetadata, options ...ClientOption) *Client {
	c := &Client{
		clientId:     clientId,
		clientSecret: clientSecret,
		metadata:     metadata,
	}

	for _, opt := range options {
		opt.Apply(c)
	}

	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}

	return c
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (TokenResponse, error) {
	form := make(url.Values)
	form.Set(GrantType, RefreshToken)
	form.Set(RefreshToken, refreshToken)

	return c.requestToken(ctx, form)
}

func (c *Client) requestToken(ctx context.Context, form url.Values) (TokenResponse, error) {
	form.Set(ClientId, c.clientId)
	form.Set(ClientSecret, c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, errors.New(resp.Status)
	}

	var tr TokenResponse
	return tr, json.NewDecoder(resp.Body).Decode(&tr)
}
