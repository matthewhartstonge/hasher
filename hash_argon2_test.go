package hasher_test

import (
	// Standard Library Imports
	"context"
	"testing"

	// External Imports
	"github.com/matthewhartstonge/argon2"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"

	// Internal Imports
	"github.com/matthewhartstonge/hasher"
)

// TestArgon2_ImplementsHasher ensures that Argon2 implements the fosite.Hasher
// interface.
func TestArgon2_ImplementsHasher(t *testing.T) {
	v := &hasher.Argon2{}
	var i interface{} = v
	_, ok := i.(fosite.Hasher)
	assert.Equal(t, true, ok)
}

// TestArgon2Hash ensures that a hash is returned from the Argon2 Hasher
func TestArgon2Hash(t *testing.T) {
	h := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(context.Background(), password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	assert.NotEqual(t, hash, password)
}

// TestArgon2CompareEquals ensures a password can be verified successfully when decoded
func TestArgon2CompareEquals(t *testing.T) {
	h := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(context.Background(), password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(context.Background(), hash, password)
	assert.Nil(t, err)
}

// TestArgon2CompareEquals ensures a compare errors when a presented clear text password does not match the original
func TestArgon2CompareDifferent(t *testing.T) {
	h := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(context.Background(), password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(context.Background(), hash, []byte("911650fc-df29-4622-8c6f-f43cbacd1ece"))
	assert.NotNil(t, err)
}
