package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/httphandler"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func init() {
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, let's default to info
	if !ok {
		lvl = "info"
	}
	// parse string, this is built-in feature of logrus
	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.InfoLevel
	}
	// set global log level
	logrus.SetLevel(ll)
}

func main() {
	ctx := context.Background()
	options, err := options.LoadOptions()
	if err != nil {
		logrus.Errorf("failed to load options: %s", err)
		os.Exit(1)
	}

	provider, err := oidc.NewProvider(ctx, options.Issuer)
	if err != nil {
		panic(err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/%s", options.AuthDomain, options.RedirectURL),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcConfig := &oidc.Config{
		ClientID: options.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	// http handler
	state := uuid.New().String()
	http.HandleFunc("/", httphandler.RootHandler(ctx, state, oauth2Config, verifier))
	http.HandleFunc(fmt.Sprintf("/%s", options.RedirectURL), httphandler.CallbackHandler(ctx, state, oauth2Config, verifier))
	http.ListenAndServe(options.BindAddress, nil)
}
