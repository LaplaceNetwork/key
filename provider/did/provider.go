// Package did Ontology Distributed Identification Protocol impelement
package did

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/btcsuite/btcutil/base58"
	"github.com/laplacenetwork/key/internal/hash160"

	"github.com/dynamicgo/xerrors"
	"github.com/laplacenetwork/key"
	"github.com/laplacenetwork/key/internal/ecdsax"
	"github.com/laplacenetwork/key/internal/secp256k1"
)

var version = byte(18)

func pubKeyToAddress(pub *ecdsa.PublicKey) string {

	pubBytes := ecdsax.PublicKeyBytes(pub)

	var nonce []byte

	if len(pubBytes) < 32 {
		nonce = make([]byte, 32)
		copy(nonce[:], pubBytes)
	} else {
		nonce = pubBytes[:32]
	}

	hashed := hash160.Hash160(nonce)

	hasher := sha256.New()

	hasher.Write(hashed)

	sum := hasher.Sum(nil)

	hasher.Reset()

	hasher.Write(sum)

	sum = hasher.Sum(nil)

	sum = sum[:3]

	did := append(hashed, sum...)

	return "did:lpt:" + base58.CheckEncode(did, version)
}

type didImpl struct {
	provider key.Provider
	key      *ecdsa.PrivateKey
	address  string // address
}

func (key *didImpl) Address() string {
	return key.address
}

func (key *didImpl) Provider() key.Provider {
	return key.provider
}

func (key *didImpl) PriKey() []byte {
	return ecdsax.PrivateKeyBytes(key.key)
}

func (key *didImpl) PubKey() []byte {
	return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

func (key *didImpl) SetBytes(priKey []byte) {

	key.key = ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	key.address = pubKeyToAddress(&key.key.PublicKey)
}

func (key *didImpl) Sign(hashed []byte) ([]byte, error) {
	return nil, nil
}

func (key *didImpl) Verify(sig []byte, hashed []byte) bool {
	return false
}

type providerIml struct {
}

func (provider *providerIml) Name() string {
	return "did"
}

func (provider *providerIml) New() (key.Key, error) {

	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &didImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {
	privateKey := ecdsax.BytesToPrivateKey(buff, secp256k1.SECP256K1())

	return &didImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}
}

func (provider *providerIml) Encode(key key.Key, password string, writer io.Writer) error {
	return nil
}

func (provider *providerIml) Decode(password string, reader io.Reader) (key.Key, error) {
	return nil, nil
}

func init() {
	key.RegisterProvider(&providerIml{})
}
