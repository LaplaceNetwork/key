package test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/laplacenetwork/key"
	_ "github.com/laplacenetwork/key/encryptor"
	_ "github.com/laplacenetwork/key/provider"
)

func TestEthKey(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	println("address", k.Address())
}

func TestWeb3Encryptor(t *testing.T) {
	k, err := key.New("eth")

	require.NoError(t, err)

	var buff bytes.Buffer

	err = key.Encrypt("web3.standard", k, map[string]string{
		"password": "test",
	}, &buff)

	require.NoError(t, err)

	println(buff.String())

	k2, err := key.New("eth")

	require.NoError(t, err)

	err = key.Decrypt("web3.standard", k2, map[string]string{
		"password": "test",
	}, &buff)

	require.NoError(t, err)

	require.Equal(t, k.Address(), k2.Address())
	require.Equal(t, k.PriKey(), k2.PriKey())

}
