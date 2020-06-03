package forwardauth

import (
	"encoding/json"
	"net/http"
)

type AuthenticatationResult struct {
	IDToken       string
	RefreshToken  string
	IDTokenClaims *json.RawMessage
}

func (fw *ForwardAuth) HandleAuthentication(r *http.Request, state string) (*AuthenticatationResult, error) {
	var result AuthenticatationResult

	oauth2Token, err := fw.OAuth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		return &result, err
	}

	result, err = fw.VerifyToken(r.Context(), oauth2Token)
	if err != nil {
		return &result, err
	}

	return &result, nil
}

func (fw *ForwardAuth) IsAuthenticated(r *http.Request) (*AuthenticatationResult, error) {
	var result AuthenticatationResult

	// Check if we have an Auth cookie
	cookie, err := fw.GetAuthCookie(r)
	if err != nil {
		return &result, err
	}

	// check if the token is valid
	idToken, err := fw.OidcVefifier.Verify(r.Context(), cookie.Value)
	if err != nil {
		return &result, err
	}

	result = AuthenticatationResult{"rawIDToken", "oauth2Token.RefreshToken", new(json.RawMessage)}
	if err := idToken.Claims(&result.IDTokenClaims); err != nil {
		return &result, err
	}

	return &result, nil
}
