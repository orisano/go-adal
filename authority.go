package adal

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/xerrors"
)

const (
	instanceDiscoveryEndpoint = "https://login.windows.net/common/discovery/instance"
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
		return nil, xerrors.Errorf("parse url: %w", err)
	}
	if err := validateAuthorityURL(parsedURL); err != nil {
		return nil, xerrors.Errorf("validate(url=%s): %w", parsedURL.String(), err)
	}
	host, tenant, err := parseAuthority(parsedURL)
	if err != nil {
		return nil, xerrors.Errorf("parse authority(url=%s): %w", parsedURL.String(), err)
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
	host := a.URL.Host
	for _, authorityHost := range wellKnownAuthorityHosts {
		if host == authorityHost {
			a.validated = true
			return nil
		}
	}

	u, err := url.ParseRequestURI(instanceDiscoveryEndpoint)
	if err != nil {
		panic(err)
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
		return xerrors.Errorf("instance discovery request(expected=2xx, actual=%s)", resp.Status)
	}

	var out struct {
		TenantDiscoveryEndpoint string `json:"tenant_discovery_endpoint"`
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&out); err != nil {
		return xerrors.Errorf("parse instance discovery response: %w", err)
	}
	_, _ = io.Copy(ioutil.Discard, resp.Body)
	if len(out.TenantDiscoveryEndpoint) == 0 {
		return xerrors.New("`tenant_discovery_endpoint` was not found")
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
	if aURL.Scheme != "https" {
		return xerrors.New("the authority url must be an https endpoint")
	}
	if len(aURL.RawQuery) != 0 {
		return xerrors.New("the authority url must not have a query string")
	}
	return nil
}

func parseAuthority(aURL *url.URL) (string, string, error) {
	host := aURL.Host
	pathParts := strings.Split(aURL.Path, "/")
	if len(pathParts) == 1 || len(pathParts[1]) == 0 {
		return "", "", xerrors.New("could not determine tenant")
	}
	tenant := pathParts[1]
	return host, tenant, nil
}
