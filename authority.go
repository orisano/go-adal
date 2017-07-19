package adal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	instanceDiscoveryEndpoint = "https://login.windows.net/common/discovery/instance"
)

var (
	wellKnownAuthorityHosts = []string{
		"login.windows.net",
		"login.microsoftonline.com",
		"login.chinacloudapi.cn",
		"login-us.microsoftonline.com",
		"login.microsoftonline.de",
	}
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
	}, nil
}

func (a *Authority) baseURL() string {
	return fmt.Sprintf("https://%s/%s", a.Host, a.Tenant)
}

func (a *Authority) AuthorityURL() string {
	return a.baseURL() + "/oauth2/authorize"
}

func (a *Authority) TokenEndpoint() string {
	return a.baseURL() + "/oauth2/token"
}

func (a *Authority) DeviceEndpoint() string {
	return a.baseURL() + "/oauth2/devicecode"
}

func (a *Authority) Validate() error {
	if a.Validated {
		return nil
	}
	hostname := a.URL.Hostname()
	for _, authorityHost := range wellKnownAuthorityHosts {
		if hostname == authorityHost {
			a.Validated = true
			return nil
		}
	}

	u, err := url.ParseRequestURI(instanceDiscoveryEndpoint)
	if err != nil {
		return err
	}

	query := url.Values{}
	query.Add("authorization_endpoint", a.AuthorityURL())
	query.Add("api-version", "1.0")
	u.RawQuery = query.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || 300 <= resp.StatusCode {
		return errors.New("instance discovery request failed")
	}

	var out struct {
		TenantDiscoveryEndpoint string `json:"tenant_discovery_endpoint"`
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&out); err != nil {
		return err
	}
	if len(out.TenantDiscoveryEndpoint) == 0 {
		return errors.New("failed to parse instance discovery")
	}
	a.Validated = true
	return nil
}

func (a *Authority) IsADFSAuthority() bool {
	return strings.ToLower(a.Tenant) == "adfs"
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
	if len(pathParts) == 1 || len(pathParts[1]) == 0 {
		return "", "", errors.New("could not determine tenant")
	}
	tenant := pathParts[1]
	return host, tenant, nil
}
