package adal

type options struct {
	AuthorityHost     string
	ValidateAuthority bool
}

type option func(*options)

func defaultOption() options {
	return options{
		AuthorityHost:     WorldWideAuthority,
		ValidateAuthority: false,
	}
}

func SetAuthorityHost(authorityHost string) option {
	return func(options *options) {
		options.AuthorityHost = authorityHost
	}
}

func ValidateAuthority() option {
	return func(options *options) {
		options.ValidateAuthority = true
	}
}
