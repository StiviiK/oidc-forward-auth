package httphandler

import (
	"net/http"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
)

// CallbackHandler returns a handler function which handles the callback from oidc provider
func CallbackHandler(fw *forwardauth.ForwardAuth, options *options.Options) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// check for the csrf cookie
		state, _, err := fw.ValidateCSRFCookie(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// verify the state
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		// handle the authentication
		authResult, err := fw.HandleAuthentication(r, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// clear the csrf cookie
		http.SetCookie(w, fw.ClearCSRFCookie(options))

		http.SetCookie(w, fw.MakeAuthCookie(r, options, authResult))
		http.SetCookie(w, fw.MakeRefreshAuthCookie(r, options, authResult))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}
