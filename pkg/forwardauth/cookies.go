/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package forwardauth

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/StiviiK/keycloak-traefik-forward-auth/pkg/options"
)

func getBaseCookie(options *options.Options) *http.Cookie {
	return &http.Cookie{
		Path:     "/",
		Domain:   options.CookieDomain,
		HttpOnly: true,
		Secure:   true,
	}
}

func (fw *ForwardAuth) MakeCSRFCookie(w http.ResponseWriter, r *http.Request, options *options.Options, state string) *http.Cookie {
	cookie := getBaseCookie(options)
	cookie.Name = "__auth_csrf"
	cookie.Value = fmt.Sprintf("%s|%s", fw.GetReturnUri(r), state)
	cookie.Expires = time.Now().Local().Add(time.Hour)

	return cookie
}

func (fw *ForwardAuth) ValidateCSRFCookie(r *http.Request) (state string, redirect string, error error) {
	csrfCookie, err := r.Cookie("__auth_csrf")
	if err != nil {
		return "", "", errors.New("Missing csrf cookie")
	}

	rExpression, err := regexp.Compile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	if err != nil {
		return "", "", err
	}

	data := strings.Split(csrfCookie.Value, "|")
	if len(data) != 2 {
		return "", "", errors.New("Invalid csrf value")
	}

	if !rExpression.MatchString(data[1]) {
		return "", "", errors.New("Invalid state")
	}

	return data[1], data[0], nil
}

func (fw *ForwardAuth) ClearCSRFCookie(options *options.Options) *http.Cookie {
	cookie := getBaseCookie(options)
	cookie.Name = "__auth_csrf"
	cookie.Expires = time.Now().Local().Add(time.Hour * -1)

	return cookie
}

func (fw *ForwardAuth) MakeAuthCookie(options *options.Options, authResult *AuthenticatationResult) *http.Cookie {
	cookie := getBaseCookie(options)
	cookie.Name = "__auth"
	cookie.Value = authResult.IDToken
	cookie.Expires = time.Now().Local().Add(time.Hour * 24)

	return cookie
}

func (fw *ForwardAuth) GetAuthCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie("__auth")
}

func (fw *ForwardAuth) ClearAuthCookie(options *options.Options) *http.Cookie {
	cookie := getBaseCookie(options)
	cookie.Name = "__auth"
	cookie.Expires = time.Now().Local().Add(time.Hour * -1)

	return cookie
}

func (fw *ForwardAuth) MakeRefreshAuthCookie(options *options.Options, authResult *AuthenticatationResult) *http.Cookie {
	cookie := getBaseCookie(options)
	cookie.Name = "__auth_refresh"
	cookie.Value = authResult.RefreshToken
	cookie.Expires = time.Now().Local().Add(time.Hour * 24)

	return cookie
}

func (fw *ForwardAuth) GetRefreshAuthCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie("__auth_refresh")
}

func (fw *ForwardAuth) ClearRefreshAuthCookie(options *options.Options) *http.Cookie {
	cookie := getBaseCookie(options)
	cookie.Name = "__auth_refresh"
	cookie.Expires = time.Now().Local().Add(time.Hour * -1)

	return cookie
}
