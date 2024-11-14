package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type ServerMetadata struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	JwksURI                                   string   `json:"jwks_uri"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
}

func LoadMetadataFromOAuthIssuer(ctx context.Context, issuer string) (ServerMetadata, error) {
	metadataURL := issuer

	if !strings.HasSuffix(metadataURL, "/") {
		metadataURL += "/"
	}

	metadataURL += ".well-known/oauth-authorization-server"
	return loadMetadata(ctx, metadataURL)
}

func loadMetadata(ctx context.Context, url string) (ServerMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ServerMetadata{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ServerMetadata{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ServerMetadata{}, fmt.Errorf("invalid status: %v", resp.StatusCode)
	}

	var sm ServerMetadata
	return sm, json.NewDecoder(resp.Body).Decode(&sm)
}
