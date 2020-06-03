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

func (fw *ForwardAuth) MakeCSRFCookie(w http.ResponseWriter, r *http.Request, options *options.Options, state string) *http.Cookie {
	return &http.Cookie{
		Name:     "_forward_auth_csrf",
		Value:    fmt.Sprintf("%s|%s", "//google.de", state),
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(time.Hour),
	}
}

func (fw *ForwardAuth) ValidateCSRFCookie(r *http.Request) (state string, redirect string, error error) {
	csrfCookie, err := r.Cookie("_forward_auth_csrf")
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
	return &http.Cookie{
		Name:     "_forward_auth_csrf",
		Value:    "",
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

func (fw *ForwardAuth) MakeAuthCookie(r *http.Request, options *options.Options, authResult *AuthenticatationResult) *http.Cookie {
	return &http.Cookie{
		Name:     "__auth",
		Value:    authResult.IDToken,
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(time.Hour * 24),
	}
}

func (fw *ForwardAuth) GetAuthCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie("__auth")
}

func (fw *ForwardAuth) ClearAuthCookie(options *options.Options) *http.Cookie {
	return &http.Cookie{
		Name:     "__auth",
		Value:    "",
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

func (fw *ForwardAuth) MakeRefreshAuthCookie(r *http.Request, options *options.Options, authResult *AuthenticatationResult) *http.Cookie {
	return &http.Cookie{
		Name:     "__auth_refresh",
		Value:    authResult.RefreshToken,
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(time.Hour * 24),
	}
}

func (fw *ForwardAuth) ClearRefreshAuthCookie(options *options.Options) *http.Cookie {
	return &http.Cookie{
		Name:     "__auth_refresh",
		Value:    "",
		Path:     "/",
		Domain:   fmt.Sprintf("http://%s:%d", options.AuthDomain, options.Port),
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}
