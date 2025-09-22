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
// ...
var (
	// You'll probably want this somewhere to hash user passwords
	argonHasher := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}

	// Check the api documentation of `compose.Config` for further configuration options.
	config = &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        secret,

		// Hash client secrets with argon2id!
		ClientSecretsHasher: argonHasher,

		// ...
	}
)
// ...
```

## Compatibility
The following table lists the compatible versions of hasher with fosite. 
If you are currently using this in production, it would be awesome to 
know what versions you are successfully paired with.

| hasher version | minimum fosite version | maximum fosite version | 
|---------------:|-----------------------:|-----------------------:|
|       `v5.1.X` |              `v0.49.X` |              `v0.49.X` |
|       `v5.X.X` |              `v0.25.X` |              `v0.40.X` |

### Installation
- Install [Go](https://go.dev/dl/)
- Create a new go project `go mod init`
- Run `go get github.com/matthewhartstonge/hasher/v5`
- `go build` successfully! 

## Licensing
hasher is under the Apache 2.0 License.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fmatthewhartstonge%2Fhasher.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fmatthewhartstonge%2Fhasher?ref=badge_large)
