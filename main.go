/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/httphandler"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

	// Configure an OpenID Connect aware OAuth2 client.
	fw, err := forwardauth.Create(ctx, options)
	if err != nil {
		logrus.Errorf("failed to create forward auth client: %s", err)
	}

	// http handler
	state := uuid.New().String()
	http.HandleFunc("/", httphandler.RootHandler(ctx, state, fw))
	http.HandleFunc(fmt.Sprintf("/%s", options.RedirectURL), httphandler.CallbackHandler(ctx, state, fw))
	http.ListenAndServe(options.BindAddress, nil)
}
