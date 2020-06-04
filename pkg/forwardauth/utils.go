/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package forwardauth

import (
	"fmt"
	"net/http"
	"net/url"
)

func (fw *ForwardAuth) GetReturnUri(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s://%s%s", proto, host, path)
}

func (fw *ForwardAuth) GetLogoutUri(redirectURL string, state string) string {
	logoutURL, err := url.Parse(fw.OidcProviderClaims.EndSessionURL)
	if err != nil {
		return ""
	}
	query := logoutURL.Query()
	if redirectURL != "" {
		query.Set("post_logout_redirect_uri", redirectURL)
	}
	if state != "" {
		query.Set("state", state)
	}
	logoutURL.RawQuery = query.Encode()
	return logoutURL.String()
}
