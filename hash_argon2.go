package hasher

import (
	"github.com/lhecker/argon2"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

// Argon2 implements the Hasher interface by using github.com/lhecker/Argon2.
type Argon2 struct {
	Config argon2.Config
}

// Compare compares data with an Argon2 hash and returns an error
// if the two do not match.
func (a *Argon2) Compare(hash, data []byte) error {
	ok, err := argon2.VerifyEncoded(data, hash)
	if err != nil {
		return errors.WithStack(err)
	}
	if !ok {
		return fosite.ErrRequestUnauthorized
	}
	return nil
}

// Hash creates a Argon2 hash from data or returns an error.
// The salt is automatically generated based on the length of the Salt as specified by Config.SaltLength
func (a *Argon2) Hash(data []byte) ([]byte, error) {
	s, err := a.Config.HashEncoded(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return s, nil
}
