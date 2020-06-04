/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package httphandler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RootHandler returns a handler function which handles all requests to the root
func (root *HttpHandler) logoutHandler(w http.ResponseWriter, r *http.Request, forwardedURI *url.URL) {
	logger := logrus.WithFields(logrus.Fields{
		"SourceIP":      r.Header.Get("X-Forwarded-For"),
		"RequestTarget": root.forwardAuth.GetReturnUri(r),
		"Path":          root.options.LogoutUrl,
	})

	// check for the csrf cookie
	state, redirect, err := root.forwardAuth.ValidateCSRFCookie(r)
	if err != nil {
		state := uuid.New().String()
		redirect := fmt.Sprintf("%s://%s", r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"))

		http.SetCookie(w, root.forwardAuth.MakeCSRFCookie(w, r, root.options, redirect, state))

		responseURL := fmt.Sprintf("https://%s%s/resp", root.options.AuthDomain, root.options.LogoutUrl)
		http.Redirect(w, r, root.forwardAuth.GetLogoutUri(responseURL, state), http.StatusTemporaryRedirect)
		return
	}

	// verify the state
	if forwardedURI.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	// Clear the auth information
	logger.Info("Destroying auth cookie.")
	http.SetCookie(w, root.forwardAuth.ClearAuthCookie(root.options))

	// Redirect to the base
	http.Redirect(w, r, redirect, http.StatusFound)
}
