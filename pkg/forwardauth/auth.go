package forwardauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/sirupsen/logrus"
)

type AuthenticatationResult struct {
	IDToken       string
	RefreshToken  string
	IDTokenClaims *json.RawMessage
}

func (fw *ForwardAuth) HandleAuthentication(logger *logrus.Entry, r *http.Request, state string) (*AuthenticatationResult, error) {
	var result AuthenticatationResult
	logger = logger.WithField("FunctionSource", "HandleAuthentication")

	oauth2Token, err := fw.OAuth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		logger.Error(err.Error())
		return &result, err
	}

	result, err = fw.VerifyToken(r.Context(), oauth2Token)
	if err != nil {
		logger.Error(err.Error())
		return &result, err
	}

	logger.Info("Authentication was succesfully.")
	return &result, nil
}

func (fw *ForwardAuth) IsAuthenticated(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, options *options.Options) (*Claims, error) {
	var claims Claims
	logger = logger.WithField("FunctionSource", "IsAuthenticated")

	// Check if we have an Auth cookie
	cookie, err := fw.GetAuthCookie(r)
	if err != nil {
		logger.Error(err.Error())
		return &claims, err
	}

	// check if the token is valid
	idToken, err := fw.OidcVefifier.Verify(r.Context(), cookie.Value)

	switch {
	case err == nil: // Token is valid
		logger.Info("Received valid token.")

		claims = Claims{}
		if err := idToken.Claims(&claims); err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		return &claims, nil

	case strings.Contains(err.Error(), "expired"): // Token is expired
		logger.Info("Received expired token, trying to refesh it.")

		refreshCookie, err := fw.GetRefreshAuthCookie(r)
		if err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		result, err := fw.RefreshToken(r.Context(), refreshCookie.Value)
		if err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		http.SetCookie(w, fw.MakeAuthCookie(r, options, result))
		if len(result.RefreshToken) > 0 { // Do we have an refresh token?
			http.SetCookie(w, fw.MakeRefreshAuthCookie(r, options, result))
		}

		err = json.Unmarshal(*result.IDTokenClaims, &claims)
		if err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		return &claims, nil

	case err != nil: // Other error
		logger.Error(err.Error())
		return &claims, err

	default:
		logger.Error("default case, should not happen")
		return &claims, errors.New("default case")
	}
}
