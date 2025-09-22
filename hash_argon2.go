package hasher

import (
	// Standard Library Imports
	"context"

	// External Imports
	"github.com/matthewhartstonge/argon2"
	"github.com/ory/fosite"
)

var _ fosite.Hasher = (*Argon2)(nil)

// Argon2 implements fosite.Hasher.
type Argon2 struct {
	Config argon2.Config
}

// Compare compares data with an Argon2 hash and returns an error
// if the two do not match.
func (a *Argon2) Compare(ctx context.Context, hash, data []byte) error {
	ok, err := argon2.VerifyEncoded(data, hash)
	if err != nil {
		return err
	}
	if !ok {
		return fosite.ErrRequestUnauthorized
	}
	return nil
}

// Hash creates a Argon2 hash from data or returns an error.
// The salt is automatically generated based on the length of the Salt as specified by Config.SaltLength
func (a *Argon2) Hash(ctx context.Context, data []byte) ([]byte, error) {
	s, err := a.Config.HashEncoded(data)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// New instantiates a new Argon 2 Hasher.
// Implements fosite.Hasher.
func New(config *argon2.Config) *Argon2 {
	cfg := argon2.DefaultConfig()
	if config != nil {
		cfg = *config
	}

	return &Argon2{
		Config: cfg,
	}
}
