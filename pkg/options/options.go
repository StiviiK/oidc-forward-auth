package options

import (
	"fmt"

	"github.com/caarlos0/env"
)

type Options struct {
	AuthDomain   string `env:"AUTH_DOMAIN"`
	Issuer       string `env:"ISSUER"`
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	RedirectURL  string `env:"REDIRECT_URL"`
	BindAddress  string `env:"BIND_ADDRESS"`
}

// LoadOptions parses the environment vars and the options
func LoadOptions() (*Options, error) {
	options := Options{}
	if err := env.Parse(&options); err != nil {
		return nil, fmt.Errorf("failed to parse github envrionments: %s", err)
	}

	return &options, nil
}
