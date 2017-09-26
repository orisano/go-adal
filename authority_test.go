package adal

import (
	"net/url"
	"testing"

	"github.com/pkg/errors"
)

func testInvalidNewAuthority(t *testing.T, urlStr string, validateAuthority bool) error {
	authority, err := NewAuthority(urlStr, validateAuthority)
	if authority != nil {
		t.Errorf("return invalid authority")
	}
	return err
}

func TestNewAuthority(t *testing.T) {
	t.Run("emptyURL", func(t *testing.T) {
		err := testInvalidNewAuthority(t, "", true)

		switch errors.Cause(err).(type) {
		case *url.Error:
			break
		default:
			t.Errorf("unexpected error: %+v", err)
		}
	})

	t.Run("invalidAuthorityURL", func(t *testing.T) {
		t.Run("notHTTPS", func(t *testing.T) {
			err := testInvalidNewAuthority(t, "http://login.microsoftonline.com", true)
			if err == nil {
				t.Errorf("accept not https url")
			}
		})

		t.Run("withQuery", func(t *testing.T) {
			err := testInvalidNewAuthority(t, "https://login.microsoftonline.com/?aid=abcdefghijklmnopqrstuvwxyz", true)
			if err == nil {
				t.Errorf("accept query string")
			}
		})
	})
}


