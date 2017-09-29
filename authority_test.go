package adal

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
)

func testInvalidAuthority(t *testing.T, urlStr string, validateAuthority bool) error {
	authority, err := NewAuthority(urlStr, validateAuthority)
	if authority != nil {
		t.Errorf("return invalid authority")
	}
	return err
}

func testAuthority(t *testing.T, urlStr string, validateAuthority bool) *Authority {
	authority, err := NewAuthority(urlStr, validateAuthority)
	if err != nil {
		t.Fatalf("authority construct failed: %v", err.Error())
	}
	if authority == nil {
		t.Fatal("return nil authority")
	}
	return authority
}

func TestNewAuthority(t *testing.T) {
	t.Run("emptyURL", func(t *testing.T) {
		err := testInvalidAuthority(t, "", true)

		switch errors.Cause(err).(type) {
		case *url.Error:
			break
		default:
			t.Errorf("unexpected error: %+v", err)
		}
	})

	t.Run("invalidAuthorityURL", func(t *testing.T) {
		t.Run("notHTTPS", func(t *testing.T) {
			err := testInvalidAuthority(t, "http://login.microsoftonline.com/dummy-tenant", true)
			if err == nil {
				t.Errorf("accept not https url")
			}
		})

		t.Run("withQuery", func(t *testing.T) {
			err := testInvalidAuthority(t, "https://login.microsoftonline.com/dummy-tenant/?aid=abcdefghijklmnopqrstuvwxyz", true)
			if err == nil {
				t.Errorf("accept query string")
			}
		})

		t.Run("withoutTenant", func(t *testing.T) {
			err := testInvalidAuthority(t, "https://login.microsoftonline.com", true)
			if err == nil {
				t.Errorf("accept without tenant")
			}
		})
	})
}

func TestAuthority_AuthorityURL(t *testing.T) {
	u := "https://my.active-directory.url/tenant"
	authority := testAuthority(t, u, true)

	expected := u + "/oauth2/authorize"
	actual := authority.AuthorityURL()
	if actual != expected {
		t.Errorf("unexpected AuthorityURL. expected: %v, actual: %v", expected, actual)
	}
}

func TestAuthority_TokenURL(t *testing.T) {
	u := "https://my.active-directory.url/tenant"
	authority := testAuthority(t, u, true)

	expected := u + "/oauth2/token"
	actual := authority.TokenURL()
	if actual != expected {
		t.Errorf("unexpected TokenURL. expected: %v, actual: %v", expected, actual)
	}
}

func TestAuthority_DeviceURL(t *testing.T) {
	u := "https://my.active-directory.url/tenant/"
	authority := testAuthority(t, u, true)

	expected := u + "oauth2/devicecode"
	actual := authority.DeviceURL()
	if actual != expected {
		t.Errorf("unexpected DeviceURL. expected: %v, actual: %v", expected, actual)
	}
}

func TestAuthority_Validate(t *testing.T) {
	t.Run("wellKnownAuthorityHostCase", func(t *testing.T) {
		authority := testAuthority(t, "https://login.microsoftonline.com/tenant", true)
		err := authority.Validate(http.DefaultClient)
		if err != nil {
			t.Errorf("wellKnownAuthorityHost rejected: %v", err)
		}
		if !authority.Validated() {
			t.Errorf("validation failed")
		}
	})

	t.Run("tenantDiscoveryNotFoundCase", func(t *testing.T) {
		authority := testAuthority(t, "https://login.myactivedirectory.localhost/dummy.tenant.localhost", true)
		err := authority.Validate(http.DefaultClient)
		if err == nil {
			t.Errorf("invalid tenant accepted")
		}
		if authority.Validated() {
			t.Errorf("wrong status")
		}
	})
}
