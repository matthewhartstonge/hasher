package hasher_test

import (
	"testing"

	"github.com/matthewhartstonge/argon2"
	"github.com/matthewhartstonge/hasher/v2"
	"github.com/stretchr/testify/assert"
)

// TestArgon2Hash ensures that a hash is returned from the Argon2 Hasher
func TestArgon2Hash(t *testing.T) {
	h := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	assert.NotEqual(t, hash, password)
}

//// TestArgon2HashLibErr purposely causes the underlying argon2 lib to error to ensure it is reported up the stack
// todo: reinstate tests once upstream has added in validation errors
//func TestArgon2HashLibErr(t *testing.T) {
//	h := &hasher.Argon2{
//		Config: argon2.DefaultConfig(),
//	}
//	h.Config.MemoryCost = 1
//	password := []byte("foo")
//	hash, err := h.Hash(password)
//	assert.Empty(t, hash)
//	assert.NotNil(t, err)
//	assert.NotEqual(t, hash, password)
//}

// TestArgon2CompareEquals ensures a password can be verified successfully when decoded
func TestArgon2CompareEquals(t *testing.T) {
	h := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(hash, password)
	assert.Nil(t, err)
}

// TestArgon2CompareEquals ensures a compare errors when a presented clear text password does not match the original
func TestArgon2CompareDifferent(t *testing.T) {
	h := &hasher.Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(hash, []byte("911650fc-df29-4622-8c6f-f43cbacd1ece"))
	assert.NotNil(t, err)
}

// TestArgon2HashLibErr purposely causes the underlying argon2 lib to error to ensure it is reported up the stack
// todo: reinstate tests once upstream has added in validation errors
//func TestArgon2CompareLibErr(t *testing.T) {
//	h := &hasher.Argon2{
//		Config: argon2.DefaultConfig(),
//	}
//	h.Config.MemoryCost = 1
//	password := []byte("foo")
//	hash, err := h.Hash(password)
//	assert.Empty(t, hash)
//	assert.NotNil(t, err)
//	err = h.Compare(hash, []byte("67e37b8c-e931-41b9-9c01-0c03629a2922"))
//	assert.NotNil(t, err)
//}
