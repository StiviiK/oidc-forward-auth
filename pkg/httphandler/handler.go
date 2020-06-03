package httphandler

import (
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

func (h *HttpHandler) Entrypoint() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return

		case uri.Path == h.options.RedirectURL:
			h.callbackHandler(w, r, uri)
			return

		case uri.Path == "/":
			h.rootHandler(w, r, uri)
			return
		}
	}
}
