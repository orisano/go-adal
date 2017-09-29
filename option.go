package adal

type options struct {
	AuthorityHost     string
	ValidateAuthority bool
}

type Option func(*options)

func defaultOption() options {
	return options{
		AuthorityHost:     WorldWideAuthority,
		ValidateAuthority: false,
	}
}

func SetAuthorityHost(authorityHost string) Option {
	return func(options *options) {
		options.AuthorityHost = authorityHost
	}
}

func ValidateAuthority() Option {
	return func(options *options) {
		options.ValidateAuthority = true
	}
}
