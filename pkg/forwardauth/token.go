/*
Copyright (c) 2020 Stefan Kürzeder <info@stivik.de>
This code is licensed under MIT license (see LICENSE for details)
*/
package forwardauth

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
)

func (fw *ForwardAuth) VerifyToken(ctx context.Context, oauth2Token *oauth2.Token) (AuthenticatationResult, error) {
	var result AuthenticatationResult

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return result, errors.New("No id_token field in oauth2 token")
	}

	idToken, err := fw.OidcVefifier.Verify(ctx, rawIDToken)
	if err != nil {
		return result, err
	}

	result = AuthenticatationResult{rawIDToken, oauth2Token.RefreshToken, new(Claims)}
	if err := idToken.Claims(&result.IDTokenClaims); err != nil {
		return result, err
	}

	return result, nil
}

func (fw *ForwardAuth) RefreshToken(ctx context.Context, refreshToken string) (*AuthenticatationResult, error) {
	var result AuthenticatationResult

	tokenSource := fw.OAuth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	oauth2Token, err := tokenSource.Token()
	if err != nil {
		return &result, err
	}

	result, err = fw.VerifyToken(ctx, oauth2Token)
	if err != nil {
		return &result, err
	}

	return &result, nil
}
