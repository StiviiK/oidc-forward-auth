/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package httphandler

import (
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

// CallbackHandler returns a handler function which handles the callback from oidc provider
func (root *HttpHandler) callbackHandler(w http.ResponseWriter, r *http.Request, forwardedURI *url.URL) {
	logger := logrus.WithFields(logrus.Fields{
		"SourceIP": r.Header.Get("X-Forwarded-For"),
		"Path":     forwardedURI.Path,
	})

	// check for the csrf cookie
	state, redirect, err := root.forwardAuth.ValidateCSRFCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// verify the state
	if forwardedURI.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	// handle the authentication
	authResult, err := root.forwardAuth.HandleAuthentication(r.Context(), logger, state, forwardedURI.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// clear the csrf cookie
	http.SetCookie(w, root.forwardAuth.ClearCSRFCookie(root.options))

	http.SetCookie(w, root.forwardAuth.MakeAuthCookie(root.options, authResult))
	//if len(authResult.RefreshToken) > 0 { // Do we have an refresh token?
	//	http.SetCookie(w, root.forwardAuth.MakeRefreshAuthCookie(root.options, authResult))
	//}
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
