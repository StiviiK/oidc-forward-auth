package httphandler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/google/uuid"
)

// RootHandler returns a handler function which handles all requests to the root
func RootHandler(fw *forwardauth.ForwardAuth, options *options.Options) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := fw.IsAuthenticated(r)
		if err != nil {
			http.SetCookie(w, fw.ClearAuthCookie(options))
			http.SetCookie(w, fw.ClearRefreshAuthCookie(options))

			state := uuid.New().String()
			http.SetCookie(w, fw.MakeCSRFCookie(w, r, options, state))
			http.Redirect(w, r, fw.OAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		claims := forwardauth.Claims{}
		err = json.Unmarshal(*result.IDTokenClaims, &claims)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read claims, %s", err), http.StatusInternalServerError)
		}

		w.Header().Set("X-Forwarded-User", claims.EMail)
		w.WriteHeader(200)
		w.Write([]byte(claims.Expiration.Time().Local().String()))
	}
}
