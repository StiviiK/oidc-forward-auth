/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package httphandler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
)

type HttpHandler struct {
	forwardAuth *forwardauth.ForwardAuth
	options     *options.Options
}

func Create(fw *forwardauth.ForwardAuth, options *options.Options) *HttpHandler {
	return &HttpHandler{
		forwardAuth: fw,
		options:     options,
	}
}

func (root *HttpHandler) Entrypoint() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return

		case uri.Path == root.options.RedirectURL:
			root.callbackHandler(w, r, uri)
			return

		case uri.Path == root.options.LogoutUrl || uri.Path == fmt.Sprintf("%s/resp", root.options.LogoutUrl):
			root.logoutHandler(w, r, uri)
			return

		default:
			root.rootHandler(w, r, uri)
			return
		}
	}
}
