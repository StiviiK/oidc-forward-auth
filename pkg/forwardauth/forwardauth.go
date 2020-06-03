/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package forwardauth

import (
	"context"
	"fmt"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/utils"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// ForwardAuth holds all important classes for our fw auth client
type ForwardAuth struct {
	OidcProvider *oidc.Provider
	OAuth2Config oauth2.Config
	OidcVefifier *oidc.IDTokenVerifier
}

// Claims represents the claims struct which we get from the identity provider
type Claims struct {
	Expiration       utils.Time `json:"exp"`
	IssuedAt         utils.Time `json:"iat"`
	Issuer           string     `json:"iss"`
	Audience         string     `json:"aud"`
	VerifiedMail     bool       `json:"email_verified"`
	Name             string     `json:"name"`
	PreferedUsername string     `json:"preferred_username"`
	GivenName        string     `json:"given_name"`
	FamilyName       string     `json:"family_name"`
	EMail            string     `json:"email"`
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
			RedirectURL:  fmt.Sprintf("https://%s%s", options.AuthDomain, options.RedirectURL),

			// Discovery returns the OAuth2 endpoints.
			Endpoint: provider.Endpoint(),

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		OidcVefifier: verifier,
	}, nil
}
