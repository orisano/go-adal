package adal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/xerrors"
)

type AuthenticationContext struct {
	Authority *Authority
}

func NewAuthenticationContext(tenant string, opts ...Option) (*AuthenticationContext, error) {
	if len(tenant) == 0 {
		return nil, xerrors.New("missing tenant")
	}

	options := defaultOption()
	for _, opt := range opts {
		opt(&options)
	}
	authorityURL := fmt.Sprintf("https://%s/%s", options.AuthorityHost, tenant)

	authority, err := NewAuthority(authorityURL, options.ValidateAuthority)
	if err != nil {
		return nil, xerrors.Errorf("create authority: %w", err)
	}
	return &AuthenticationContext{
		Authority: authority,
	}, nil
}

func (a *AuthenticationContext) Client(ctx context.Context, resource, clientID, clientSecret string) (*http.Client, error) {
	if len(resource) == 0 {
		return nil, xerrors.New("missing resource")
	}
	if len(clientID) == 0 {
		return nil, xerrors.New("missing clientID")
	}
	if len(clientSecret) == 0 {
		return nil, xerrors.New("missing clientSecret")
	}
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     a.Authority.TokenURL(),
		EndpointParams: url.Values{
			"resource": {resource},
		},
	}
	return config.Client(ctx), nil
}
