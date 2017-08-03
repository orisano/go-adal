package adal

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type AuthenticationContext struct {
	Authority *Authority
}

func NewAuthenticationContext(tenant string, opts ...option) (*AuthenticationContext, error) {
	options := defaultOption()
	for _, opt := range opts {
		opt(&options)
	}
	authorityUrl := fmt.Sprintf("https://%s/%s", options.AuthorityHost, tenant)

	authority, err := NewAuthority(authorityUrl, options.ValidateAuthority)
	if err != nil {
		return nil, errors.Wrap(err, "authority create failed")
	}
	return &AuthenticationContext{
		Authority: authority,
	}, nil
}

func (a *AuthenticationContext) TokenSourceFromClientCredentials(ctx context.Context, resource, clientID, clientSecret string) oauth2.TokenSource {
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     a.Authority.TokenURL(),
		EndpointParams: url.Values{
			"resource": {resource},
		},
	}
	return config.TokenSource(ctx)
}
