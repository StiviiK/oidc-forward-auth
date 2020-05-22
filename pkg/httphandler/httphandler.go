/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package httphandler

import (
	"context"
	"net/http"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// CallbackHandler returns a handler function which handles the callback from oidc provider
func CallbackHandler(ctx context.Context, fw *forwardauth.ForwardAuth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// check for the csrf cookie
		state, redirect, err := fw.ValidateCSRFCookie(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// handle the authentication
		_, err, statusCode := fw.HandleAuthentication(ctx, w, r, state)
		if err != nil {
			http.Error(w, err.Error(), statusCode)
			return
		}

		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// RootHandler returns a handler function which handles all requests to the root
func RootHandler(ctx context.Context, fw *forwardauth.ForwardAuth, options *options.Options) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		state, _, err := fw.ValidateCSRFCookie(r)
		if err != nil {
			state = uuid.New().String()
			http.SetCookie(w, fw.MakeCSRFCookie(w, options, state))
			http.Redirect(w, r, fw.OAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		_, err = fw.IsAuthenticated(ctx, state)
		if err != nil {
			logrus.Error(err.Error())
			http.Redirect(w, r, fw.OAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		w.Header().Set("X-Forwarded-User", "")
		w.WriteHeader(200)
	}
}
