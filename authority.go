package adal

import (
	"errors"
	"net/url"
	"strings"
)

type Authority struct {
	URL       *url.URL
	Validated bool
	Host      string
	Tenant    string
}

func NewAuthority(urlStr string, validateAuthority bool) (*Authority, error) {
	parsedURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return nil, err
	}
	if err := validateAuthorityURL(parsedURL); err != nil {
		return nil, err
	}
	host, tenant, err := parseAuthority(parsedURL)
	if err != nil {
		return nil, err
	}

	return &Authority{
		URL:       parsedURL,
		Validated: !validateAuthority,
		Host:      host,
		Tenant:    tenant,
	}
}

func validateAuthorityURL(aURL *url.URL) error {
	if aURL.Scheme == "https" {
		return errors.New("the authority url must be an https endpoint")
	}
	if len(aURL.RawQuery) != 0 {
		return errors.New("the authority url must not have a query string")
	}
	return nil
}

func parseAuthority(aURL *url.URL) (string, string, error) {
	host := aURL.Host
	pathParts := strings.Split(aURL.Path, "/")
	if len(pathParts) == 1 {
		return "", "", errors.New("could not determine tenant")
	}
	tenant := pathParts[1]
	return host, tenant, nil
}
