/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/httphandler"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
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
		logrus.Exit(1)
	}

	// Check if the required options are set
	if err := checkOptions(options); err != nil {
		logrus.Error(err.Error())
		logrus.Exit(1)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	fw, err := forwardauth.Create(ctx, options)
	if err != nil {
		logrus.Errorf("failed to create forward auth client: %s", err)
		logrus.Exit(1)
	}

	// http handler
	http.HandleFunc("/", httphandler.RootHandler(ctx, fw, options))
	http.HandleFunc(fmt.Sprintf("/%s", options.RedirectURL), httphandler.CallbackHandler(ctx, fw))

	logrus.Infof("Listening on %d", options.Port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", options.Port), nil))
}

func checkOptions(options *options.Options) error {
	if options.AuthDomain == "" {
		return errors.New("Required arg AUTH_DOMAIN is not set")
	}

	if options.Port == 0 {
		return errors.New("Required arg BIND_ADRESS is not set")
	}

	if options.ClientID == "" {
		return errors.New("Required arg CLIENT_ID is not set")
	}

	if options.ClientSecret == "" {
		return errors.New("Required arg CLIENT_SECRET is not set")
	}

	if options.Issuer == "" {
		return errors.New("Required arg ISSUER is not set")
	}

	if options.RedirectURL == "" {
		return errors.New("Required arg REDIRECT_URL is not set")
	}

	return nil
}
