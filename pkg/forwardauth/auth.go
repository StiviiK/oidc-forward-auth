/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package forwardauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
	"github.com/sirupsen/logrus"
)

type AuthenticatationResult struct {
	IDToken       string
	RefreshToken  string
	IDTokenClaims *Claims
}

func (fw *ForwardAuth) HandleAuthentication(ctx context.Context, logger *logrus.Entry, state string, code string) (*AuthenticatationResult, error) {
	var result AuthenticatationResult
	logger = logger.WithField("FunctionSource", "HandleAuthentication")

	oauth2Token, err := fw.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		logger.Error(err.Error())
		return &result, err
	}

	result, err = fw.VerifyToken(ctx, oauth2Token)
	if err != nil {
		logger.Error(err.Error())
		return &result, err
	}

	logger.Info("Authentication was succesfully.")
	return &result, nil
}

func (fw *ForwardAuth) IsAuthenticated(context context.Context, logger *logrus.Entry, w http.ResponseWriter, r *http.Request, options *options.Options) (*Claims, error) {
	var claims Claims
	logger = logger.WithField("FunctionSource", "IsAuthenticated")

	// Check if we have an Auth cookie
	cookie, err := fw.GetAuthCookie(r)
	if err != nil {
		logger.Error(err.Error())
		return &claims, err
	}

	// check if the token is valid
	idToken, err := fw.OidcVefifier.Verify(context, cookie.Value)

	switch {
	case err == nil: // Token is valid
		logger.Info("Received valid token.")

		claims = Claims{}
		if err := idToken.Claims(&claims); err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		return &claims, nil

		// Todo: Updating the cookies does sadly not work here
	case strings.Contains(err.Error(), "expired"): // Token is expired
		logger.Info("Received expired token, trying to refesh it.")

		refreshCookie, err := fw.GetRefreshAuthCookie(r)
		if err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		result, err := fw.RefreshToken(context, refreshCookie.Value)
		if err != nil {
			logger.Error(err.Error())
			return &claims, err
		}

		http.SetCookie(w, fw.MakeAuthCookie(options, result))
		if len(result.RefreshToken) > 0 { // Do we have an refresh token?
			http.SetCookie(w, fw.MakeRefreshAuthCookie(options, result))
		}

		return result.IDTokenClaims, nil

	case err != nil: // Other error
		logger.Error(err.Error())
		return &claims, err

	default:
		logger.Error("default case, should not happen")
		return &claims, errors.New("default case")
	}
}
