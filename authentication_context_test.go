package adal

import (
	"context"
	"testing"
)

func TestNewAuthenticationContext(t *testing.T) {
	t.Run("emptyTenant", func(t *testing.T) {
		ac, err := NewAuthenticationContext("")
		if err == nil {
			t.Errorf("empty tenant accepted")
		}
		if ac != nil {
			t.Errorf("return invalid AuthenticationContext")
		}
	})
	t.Run("invalidTenant", func(t *testing.T) {
		ac, err := NewAuthenticationContext("my.active-directory.localhost?q=1")
		if err == nil {
			t.Errorf("invalid tenant accepted")
		}
		if ac != nil {
			t.Errorf("return invalid AuthenticationContext")
		}
	})
	t.Run("positiveCase", func(t *testing.T) {
		tenant := "my.active-directory.localhost"
		ac, err := NewAuthenticationContext(tenant)
		if err != nil {
			t.Errorf("AuthenticationContext construct failed: %v", err)
		}
		if ac == nil {
			t.Fatalf("return nil AuthenticationContext")
		}
		if ac.Authority.Tenant != tenant {
			t.Errorf("unexpected AuthorityTenant. expect: %v, actual: %v", tenant, ac.Authority.Tenant)
		}
	})
	t.Run("withOption", func(t *testing.T) {
		authorityHost := "login.chinacloudapi.cn"
		ac, err := NewAuthenticationContext(
			"my.active-directory.localhost",
			SetAuthorityHost(authorityHost),
			ValidateAuthority(),
		)
		if err != nil {
			t.Fatalf("AuthenticationContext construct failed: %v", err)
		}
		if ac.Authority.Host != authorityHost {
			t.Errorf("unexpected AuthorityHost. expect: %v, actual: %v", authorityHost, ac.Authority.Host)
		}
	})
}

func TestAuthenticationContext_Client(t *testing.T) {
	tenant := "my.active-directory.localhost"
	resource := "https://dummy.resource.net"
	clientID := "xxxxxxxxxxxxxxxxxxxxxxxxxx"
	clientSecret := "___5oy1KvgsqA___"

	ac, err := NewAuthenticationContext(tenant)
	if err != nil {
		t.Fatalf("AuthenticationContext construct failed: %v", err)
	}

	t.Run("emptyResource", func(t *testing.T) {
		client, err := ac.Client(context.TODO(), "", clientID, clientSecret)
		if err == nil {
			t.Errorf("empty resource accepted")
		}
		if client != nil {
			t.Errorf("return invalid Client")
		}
	})

	t.Run("emptyClientID", func(t *testing.T) {
		client, err := ac.Client(context.TODO(), resource, "", clientSecret)
		if err == nil {
			t.Errorf("empty clientID accepted")
		}
		if client != nil {
			t.Errorf("return invalid Client")
		}
	})

	t.Run("emptyClientSecret", func(t *testing.T) {
		client, err := ac.Client(context.TODO(), resource, clientID, "")
		if err == nil {
			t.Errorf("empty clientSecret accepted")
		}
		if client != nil {
			t.Errorf("return invalid Client")
		}
	})

	t.Run("positiveCase", func(t *testing.T) {
		client, err := ac.Client(context.TODO(), resource, clientID, clientSecret)
		if err != nil {
			t.Errorf("Client construct failed: %v", err)
		}
		if client == nil {
			t.Errorf("return nil Client")
		}
	})
}
