# fosite-hasher-argon2
[![Build Status](https://travis-ci.org/MatthewHartstonge/hasher.svg?branch=master)](https://travis-ci.org/MatthewHartstonge/hasher) [![Coverage Status](https://coveralls.io/repos/github/MatthewHartstonge/hasher/badge.svg?branch=master)](https://coveralls.io/github/MatthewHartstonge/hasher?branch=master)

fosite-hasher-argon2 provides an Argon2 based password hasher that conforms to the hasher interface required by fosite.

**Table of contents**
- [Documentation](#documentation)
  - [Development](#development)
    - [Linux](#linux)
    - [Windows 32-bit](#windows-32-bit)
    - [Windows 64-bit](#windows-64-bit)
  - [Example](#example)

## Documentation
### Development
Currently there is no 'pure' Golang implementation of the Argon 1.3 specification, the version of which doesn't 
currently have a known attack vector. In the meantime, this requires having `GCC` installed to allow complation with 
`CGO`. Follow the steps below to ensure you can use the Argon2 hasher on your given environments

#### Linux
- On Debian/Ubuntu run `sudo apt-get update && sudo apt-get install build-essential`
- Install [glide](http://glide.sh/) - A golang package manager
- Run `glide install`
- `go build` successfully! 

#### Windows 32-bit
- Install [MinGW for x86](https://sourceforge.net/projects/mingw/files/latest/download?source=files)
- Add `C:\MinGW\bin` to path
- Select and install `gcc-core`
- Select and install `gcc-g++`
- Install [glide](http://glide.sh/) - A golang package manager
- Run `glide install`
- `go build` successfully!

#### Windows 64-bit
- Install [Cygwin](https://cygwin.com/setup-x86_64.exe)
- Add `C:\cygwin64\bin` to path
- Select and Install `x86_64-w64-mingw32-gcc-core`
- Select and Install `x86_64-w64-mingw32-gcc-g++`
- Change all file names in `C:\cygwin64\bin` by removing `x86_64-w64-mingw32-` which is prepended to all files we need to use..
- Install [glide](http://glide.sh/) - A golang package manager
- Run `glide install`
- `go build` successfully!

### Example
Following the [fosite-example/authorizationserver](https://github.com/ory/fosite-example/blob/master/authorizationserver/oauth2.go) 
example, we can extend this to add support for the argon2 hasher via the compose configuration. I have used a custom 
fosite Compose function, `Argon2Compose`, which allows taking in a custom hasher.

```go
import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/MatthewHartstonge/hasher"
	"github.com/lhecker/argon2"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"time"
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
var argon2DefaultConfiguration = &hasher.Argon2{
	Config: argon2.DefaultConfig(),
}

// To customise the Argon2 config use the following:
//var argon2CustomConfig = &hasher.Argon2{
//	Config: argon2.Config{
//		HashLength:  32,
//		SaltLength:  16,
//		TimeCost:    3,
//		MemoryCost:  1 << 12,
//		Parallelism: 1,
//		Mode:        argon2.ModeArgon2i,
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