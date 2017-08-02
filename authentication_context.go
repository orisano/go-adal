package adal

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2/clientcredentials"
)

type AuthenticationContext struct {
	Authority *Authority
}

func NewAuthenticationContext(urlStr string, validateAuthority bool) (*AuthenticationContext, error) {
	authority, err := NewAuthority(urlStr, validateAuthority)
	if err != nil {
		return nil, errors.Wrap(err, "authority create failed")
	}
	return &AuthenticationContext{
		Authority: authority,
	}, nil
}

func (a *AuthenticationContext) ClientFromClientCredentials(ctx context.Context, resource, clientID, clientSecret string) *http.Client {
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     a.Authority.TokenURL(),
		EndpointParams: url.Values{
			"resource": {resource},
		},
	}
	return config.Client(ctx)
}
