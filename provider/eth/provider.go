package eth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/sha3"

	"github.com/laplacenetwork/key"
	"github.com/laplacenetwork/key/internal/ecdsax"
	"github.com/laplacenetwork/key/internal/secp256k1"
)

func pubKeyToAddress(pub *ecdsa.PublicKey) string {
	pubBytes := ecdsax.PublicKeyBytes(pub)

	hasher := sha3.NewKeccak256()

	hasher.Write(pubBytes[1:])

	pubBytes = hasher.Sum(nil)[12:]

	if len(pubBytes) > 20 {
		pubBytes = pubBytes[len(pubBytes)-20:]
	}

	address := make([]byte, 20)

	copy(address[20-len(pubBytes):], pubBytes)

	unchecksummed := hex.EncodeToString(address)

	sha := sha3.NewKeccak256()

	sha.Write([]byte(unchecksummed))

	hash := sha.Sum(nil)

	result := []byte(unchecksummed)

	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}

	return "0x" + string(result)
}

type keyImpl struct {
	provider key.Provider
	key      *ecdsa.PrivateKey
	address  string // address
}

func (key *keyImpl) Address() string {
	return key.address
}

func (key *keyImpl) Provider() key.Provider {
	return key.provider
}

func (key *keyImpl) PriKey() []byte {
	return ecdsax.PrivateKeyBytes(key.key)
}

func (key *keyImpl) PubKey() []byte {
	return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

func (key *keyImpl) SetBytes(priKey []byte) {
	key.key = ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	key.address = pubKeyToAddress(&key.key.PublicKey)
}

func (key *keyImpl) Sign(hashed []byte) ([]byte, error) {
	return nil, nil
}

func (key *keyImpl) Verify(sig []byte, hashed []byte) bool {
	return false
}

type providerIml struct {
}

func (provider *providerIml) Name() string {
	return "eth"
}

func (provider *providerIml) New() (key.Key, error) {

	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, xerrors.Wrapf(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &keyImpl{
		provider: provider,
		key:      privateKey,
		address:  pubKeyToAddress(&privateKey.PublicKey),
	}, nil
}

func (provider *providerIml) FromBytes(buff []byte) key.Key {
	privateKey := ecdsax.BytesToPrivateKey(buff, secp256k1.SECP256K1())

	return &keyImpl{
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
