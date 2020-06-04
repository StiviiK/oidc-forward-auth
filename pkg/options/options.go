/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package options

import (
	"fmt"

	"github.com/caarlos0/env"
)

type Options struct {
	Issuer       string `env:"ISSUER"`
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	AuthDomain   string `env:"AUTH_DOMAIN"`
	CookieDomain string `env:"COOKIE_DOMAIN"`
	Port         int    `env:"PORT" envDefault:"4181"`
	RedirectURL  string `env:"REDIRECT_URL" envDefault:"/auth/resp"`
}

// LoadOptions parses the environment vars and the options
func LoadOptions() (*Options, error) {
	options := Options{}
	if err := env.Parse(&options); err != nil {
		return nil, fmt.Errorf("failed to parse options: %s", err)
	}

	return &options, nil
}
