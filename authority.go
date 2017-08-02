package adal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
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
	URL    *url.URL
	Host   string
	Tenant string

	validated bool
}

func NewAuthority(urlStr string, validateAuthority bool) (*Authority, error) {
	parsedURL, err := url.ParseRequestURI(urlStr)
	if err != nil {
		return nil, errors.Wrapf(err, "url parse failed: %s", urlStr)
	}
	if err := validateAuthorityURL(parsedURL); err != nil {
		return nil, errors.Wrapf(err, "invalid authority url: %s", parsedURL.String())
	}
	host, tenant, err := parseAuthority(parsedURL)
	if err != nil {
		return nil, errors.Wrapf(err, "authority parse failed")
	}

	return &Authority{
		URL:       parsedURL,
		Host:      host,
		Tenant:    tenant,
		validated: !validateAuthority,
	}, nil
}

func (a *Authority) baseURL() string {
	return fmt.Sprintf("https://%s/%s", a.Host, a.Tenant)
}

func (a *Authority) AuthorityURL() string {
	return a.baseURL() + "/oauth2/authorize"
}

func (a *Authority) TokenURL() string {
	return a.baseURL() + "/oauth2/token"
}

func (a *Authority) DeviceURL() string {
	return a.baseURL() + "/oauth2/devicecode"
}

func (a *Authority) Validate(httpClient *http.Client) error {
	if a.validated {
		return nil
	}
	hostname := a.URL.Hostname()
	for _, authorityHost := range wellKnownAuthorityHosts {
		if hostname == authorityHost {
			a.validated = true
			return nil
		}
	}

	u, err := url.ParseRequestURI(instanceDiscoveryEndpoint)
	if err != nil {
		return errors.Wrapf(err, "invalid instance discovery endpoint, make a github issue")
	}

	query := url.Values{}
	query.Add("authorization_endpoint", a.AuthorityURL())
	query.Add("api-version", "1.0")
	u.RawQuery = query.Encode()

	resp, err := httpClient.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || 300 <= resp.StatusCode {
		return errors.Errorf("instance discovery request failed: expected 2xx, actual %s", resp.Status)
	}

	var out struct {
		TenantDiscoveryEndpoint string `json:"tenant_discovery_endpoint"`
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&out); err != nil {
		return errors.Wrapf(err, "failed to parse response")
	}
	if len(out.TenantDiscoveryEndpoint) == 0 {
		return errors.New("failed to parse instance discovery")
	}
	a.validated = true
	return nil
}

func (a *Authority) IsADFSAuthority() bool {
	return strings.ToLower(a.Tenant) == "adfs"
}

func (a *Authority) Validated() bool {
	return a.validated
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
