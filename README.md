# fosite-hasher-argon2
[![Go Report Card](https://goreportcard.com/badge/github.com/matthewhartstonge/hasher)](https://goreportcard.com/report/github.com/matthewhartstonge/hasher) [![Build Status](https://travis-ci.org/matthewhartstonge/hasher.svg?branch=master)](https://travis-ci.org/matthewhartstonge/hasher) [![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fmatthewhartstonge%2Fhasher.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fmatthewhartstonge%2Fhasher?ref=badge_shield)

fosite-hasher-argon2 provides an Argon2 based password hasher that conforms to 
the hasher interface required by fosite.

**Table of contents**
- [Example](#example)
- [Compatibility](#compatibility)
- [Development](#development)
  - [Installation](#installation)

## Example
Following the [fosite-example/authorizationserver](https://github.com/ory/fosite-example/blob/master/authorizationserver/oauth2.go) 
example, we can extend this to add support for the argon2 hasher via the compose 
configuration. I have used a custom fosite Compose function, `Argon2Compose`, 
which allows taking in a custom hasher.

```go
package myoauth

import (
	"crypto/rand"
	"crypto/rsa"
	"time"
	
	"github.com/matthewhartstonge/argon2"
	"github.com/matthewhartstonge/hasher"
	
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

// This is the exemplary storage that contains:
// * an OAuth2 Client with id "my-client" and secret "foobar" capable of all oauth2 and open id connect grant and response types.
// * a User for the resource owner password credentials grant type with usename "peter" and password "secret".
//
// You will most likely replace this with your own logic once you set up a real world application.
var store = storage.NewMemoryStore()

// check the api docs of compose.Config for further configuration options
var config = &compose.Config{
	AccessTokenLifespan: time.Minute * 30,
	// ...
}

// Because we are using oauth2 and open connect id, we use this little helper to combine the two in one
// variable.
var strat = compose.CommonStrategy{
	// alternatively you could use:
	//  OAuth2Strategy: compose.NewOAuth2JWTStrategy(mustRSAKey())
	CoreStrategy: compose.NewOAuth2HMACStrategy(config, []byte("some-super-cool-secret-that-nobody-knows")),

	// open id connect strategy
	OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(mustRSAKey()),
}

// For a default Argon2 configuration setup
var argon2DefaultConfiguration = hasher.New(nil)

// To customise the Argon2 config use the following:
//var argon2CustomConfig = &hasher.Argon2{
//	Config: argon2.Config{
//		HashLength:  32,
//		SaltLength:  16,
//		TimeCost:    3,
//		MemoryCost:  64*1024,
//		Parallelism: 4,
//		Mode:        argon2.ModeArgon2id,
//		Version:     argon2.Version13,
//	},
//}

var oauth2 = Argon2Compose(
	config,
	store,
	strat,
	argon2DefaultConfiguration,

	// enabled handlers
	compose.OAuth2AuthorizeExplicitFactory,
	compose.OAuth2AuthorizeImplicitFactory,
	compose.OAuth2ClientCredentialsGrantFactory,
	compose.OAuth2RefreshTokenGrantFactory,
	compose.OAuth2ResourceOwnerPasswordCredentialsFactory,

	compose.OAuth2TokenRevocationFactory,
	compose.OAuth2TokenIntrospectionFactory,

	// be aware that open id connect factories need to be added after oauth2 factories to work properly.
	compose.OpenIDConnectExplicitFactory,
	compose.OpenIDConnectImplicitFactory,
	compose.OpenIDConnectHybridFactory,
)

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//  session = new(fosite.DefaultSession)
func newSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:    "https://fosite.my-application.com",
			Subject:   user,
			Audience:  "https://my-client.my-application.com",
			ExpiresAt: time.Now().Add(time.Hour * 6),
			IssuedAt:  time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}

func mustRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return key
}

// Compose makes use of interface{} types in order to be able to handle a all types of stores, strategies and handlers.
func Argon2Compose(config *compose.Config, storage interface{}, strategy interface{}, hasher interface{}, factories ...compose.Factory) fosite.OAuth2Provider {
	if hasher == nil {
		hasher = &fosite.BCrypt{WorkFactor: config.GetHashCost()}
	}
	f := &fosite.Fosite{
		Store: storage.(fosite.Storage),
		AuthorizeEndpointHandlers:  fosite.AuthorizeEndpointHandlers{},
		TokenEndpointHandlers:      fosite.TokenEndpointHandlers{},
		TokenIntrospectionHandlers: fosite.TokenIntrospectionHandlers{},
		RevocationHandlers:         fosite.RevocationHandlers{},
		Hasher:                     hasher.(fosite.Hasher),
		ScopeStrategy:              fosite.HierarchicScopeStrategy,
	}

	for _, factory := range factories {
		res := factory(config, storage, strategy)
		if ah, ok := res.(fosite.AuthorizeEndpointHandler); ok {
			f.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(fosite.TokenEndpointHandler); ok {
			f.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(fosite.TokenIntrospector); ok {
			f.TokenIntrospectionHandlers.Append(tv)
		}
		if rh, ok := res.(fosite.RevocationHandler); ok {
			f.RevocationHandlers.Append(rh)
		}
	}

	return f
}
```

## Compatibility
The following table lists the compatible versions of hasher with fosite. 
If you are currently using this in production, it would be awesome to 
know what versions you are successfully paired with.

| hasher version  | minimum fosite version | maximum fosite version | 
|----------------:|-----------------------:|-----------------------:|
|       `v4.X.X`  |              `v0.25.X` |              `v0.30.X` |
|       `v3.2.X`  |              `v0.25.X` |              `v0.30.X` |
|       `v3.1.X`  |              `v0.24.X` |              `v0.24.X` |
|       `v3.0.X`  |              `v0.23.X` |              `v0.23.X` |


## Development
- For version 4 we have migrated to `go mod`.
- For version 3 and below, install `dep`, run `dep ensure` and build!
    - Require version 3 with go mod? run `go get github.com/matthewhartstonge/hasher@v3.3.2+incompatible`

### Installation
- Install [Go](https://golang.github.io/dep/)
- Create a new go project `go mod init`
- Run `go get github.com/matthewhartstonge/hasher/v4`
- `go build` successfully! 

## Licensing
hasher is under the Apache 2.0 License.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fmatthewhartstonge%2Fhasher.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fmatthewhartstonge%2Fhasher?ref=badge_large)
