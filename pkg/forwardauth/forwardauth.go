package forwardauth

import (
	"context"
	"fmt"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// ForwardAuth holds all important classes for our fw auth client
type ForwardAuth struct {
	OidcProvider *oidc.Provider
	OAuth2Config oauth2.Config
	OidcVefifier *oidc.IDTokenVerifier
}

// Create creates a new fw auth client from our options
func Create(ctx context.Context, options *options.Options) (*ForwardAuth, error) {
	provider, err := oidc.NewProvider(ctx, options.Issuer)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: options.ClientID,
	})

	return &ForwardAuth{
		OidcProvider: provider,
		OAuth2Config: oauth2.Config{
			ClientID:     options.ClientID,
			ClientSecret: options.ClientSecret,
			RedirectURL:  fmt.Sprintf("%s/%s", options.AuthDomain, options.RedirectURL),

			// Discovery returns the OAuth2 endpoints.
			Endpoint: provider.Endpoint(),

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		OidcVefifier: verifier,
	}, nil
}
