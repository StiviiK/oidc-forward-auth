package httphandler

import (
	"net/http"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/forwardauth"
	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RootHandler returns a handler function which handles all requests to the root
func RootHandler(fw *forwardauth.ForwardAuth, options *options.Options) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logrus.WithFields(logrus.Fields{
			"SourceIP": r.Header.Get("X-Forwarded-For"),
			"Path":     r.URL.Path,
		})

		claims, err := fw.IsAuthenticated(logger, w, r, options)
		if err != nil {
			logger = logger.WithField("FunctionSource", "RootHandler")
			logger.Warn("IsAuthenticated failed, initating login flow.")

			http.SetCookie(w, fw.ClearAuthCookie(options))
			http.SetCookie(w, fw.ClearRefreshAuthCookie(options))

			state := uuid.New().String()
			http.SetCookie(w, fw.MakeCSRFCookie(w, r, options, state))
			http.Redirect(w, r, fw.OAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		w.Header().Set("X-Forwarded-User", claims.EMail)
		w.WriteHeader(200)
		w.Write([]byte(claims.Expiration.Time().Local().String()))
	}
}
