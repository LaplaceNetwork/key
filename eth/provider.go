package eth

import (
	"crypto/ecdsa"
	"io"

	"github.com/laplacenetwork/key"
)

type keyImpl struct {
	key *ecdsa.PrivateKey
}

type providerIml struct {
}

func (provider *providerIml) Name() string {
	return "eth"
}

func (provider *providerIml) New() (key.Key, error) {
	return nil, nil
}

func (provider *providerIml) Encode(key key.Key, password string, writer io.Writer) error {
	return nil
}

func (provider *providerIml) Decode(password string, reader io.Reader) (key.Key, error) {
	return nil, nil
}
