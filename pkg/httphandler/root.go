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
func (root *HttpHandler) rootHandler(w http.ResponseWriter, r *http.Request, forwardedURI *url.URL) {
	redirect := fmt.Sprintf("%s://%s%s", r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Uri"))
	logger := logrus.WithFields(logrus.Fields{
		"SourceIP":      r.Header.Get("X-Forwarded-For"),
		"RequestTarget": redirect,
		"Path":          "/",
	})

	claims, err := root.forwardAuth.IsAuthenticated(r.Context(), logger, w, r, root.options)
	if err != nil {
		logger = logger.WithField("FunctionSource", "RootHandler")
		logger.Warn("IsAuthenticated failed, initating login flow.")

		http.SetCookie(w, root.forwardAuth.ClearAuthCookie(root.options))
		//http.SetCookie(w, root.forwardAuth.ClearRefreshAuthCookie(root.options))

		state := uuid.New().String()
		http.SetCookie(w, root.forwardAuth.MakeCSRFCookie(w, r, root.options, redirect, state))
		http.Redirect(w, r, root.forwardAuth.OAuth2Config.AuthCodeURL(state), http.StatusTemporaryRedirect)
		return
	}

	w.Header().Set("X-Forwarded-User", claims.Email)
	w.WriteHeader(http.StatusOK)
}
