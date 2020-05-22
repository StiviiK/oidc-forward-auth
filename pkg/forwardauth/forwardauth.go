package forwardauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

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
			RedirectURL:  fmt.Sprintf("http://%s:%d/%s", options.AuthDomain, options.Port, options.RedirectURL),

			// Discovery returns the OAuth2 endpoints.
			Endpoint: provider.Endpoint(),

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		OidcVefifier: verifier,
	}, nil
}

// Member methods

type AuthenticatationResult struct {
	IDToken       string
	RefreshToken  string
	IDTokenClaims *json.RawMessage
}

func (fw *ForwardAuth) HandleAuthentication(ctx context.Context, w http.ResponseWriter, r *http.Request, state string) (*AuthenticatationResult, error, int) {
	var result AuthenticatationResult
	if r.URL.Query().Get("state") != state {
		return &result, errors.New("state did not match"), http.StatusBadRequest
	}

	oauth2Token, err := fw.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		return &result, err, http.StatusInternalServerError
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return &result, errors.New("No id_token field in oauth2 token"), http.StatusInternalServerError
	}

	idToken, err := fw.OidcVefifier.Verify(ctx, rawIDToken)
	if err != nil {
		return &result, err, http.StatusInternalServerError
	}

	result = AuthenticatationResult{rawIDToken, oauth2Token.RefreshToken, new(json.RawMessage)}
	if err := idToken.Claims(&result.IDTokenClaims); err != nil {
		return &result, err, http.StatusInternalServerError
	}

	return &result, nil, http.StatusOK
}

func (fw *ForwardAuth) IsAuthenticated(ctx context.Context, state string) (*AuthenticatationResult, error) {
	var result AuthenticatationResult
	var token string

	idToken, err := fw.OidcVefifier.Verify(ctx, token)
	if err != nil {
		return &result, err
	}

	result = AuthenticatationResult{"rawIDToken", "oauth2Token.RefreshToken", new(json.RawMessage)}
	if err := idToken.Claims(&result.IDTokenClaims); err != nil {
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		//return &result, err, http.StatusInternalServerError
	}

	return &result, nil
}

func (fw *ForwardAuth) MakeCSRFCookie(w http.ResponseWriter, options *options.Options, state string) *http.Cookie {
	return &http.Cookie{
		Name:     "_forward_auth_csrf",
		Value:    fmt.Sprintf("%s|%s", "http://google.com", state),
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(99999999999999999),
	}
}

func (fw *ForwardAuth) ValidateCSRFCookie(r *http.Request) (state string, redirect string, error error) {
	csrfCookie, err := r.Cookie("_forward_auth_csrf")
	if err != nil {
		return "", "", errors.New("Missing csrf cookie")
	}

	rExpression, err := regexp.Compile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	if err != nil {
		return "", "", err
	}

	data := strings.Split(csrfCookie.Value, "|")
	if len(data) != 2 {
		return "", "", errors.New("Invalid csrf value")
	}

	if !rExpression.MatchString(data[1]) {
		return "", "", errors.New("Invalid state")
	}

	return data[1], data[0], nil
}
