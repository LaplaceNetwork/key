package key // import "github.com/laplacenetwork/key"

import (
	"errors"
	"io"

	"github.com/dynamicgo/xerrors"

	"github.com/dynamicgo/injector"
)

// Errors
var (
	ErrDriver    = errors.New("unknown driver")
	ErrPublicKey = errors.New("invalid public key")
)

// Key blockchain key facade
type Key interface {
	Address() string                    // address display string
	PriKey() []byte                     // private key byte array
	PubKey() []byte                     // public key byte array
	SetBytes(priKey []byte)             // set private key bytes
	Sign(hashed []byte) ([]byte, error) // sign the hashed message
}

// Provider the key service provider
type Provider interface {
	Name() string      // driver name
	New() (Key, error) // create new key
	Verify(pubkey []byte, sig []byte, hash []byte) bool
	PublicKeyToAddress(pubkey []byte) (string, error)
}

// RecoverableProvider .
type RecoverableProvider interface {
	Provider
	Recover(sig []byte, hash []byte) (pubkey []byte, err error)
}

// Encryptor .
type Encryptor interface {
	Encrypt(key Key, attrs map[string]string, writer io.Writer) error
	Decrypt(key Key, attrs map[string]string, reader io.Reader) error
}

// RegisterProvider register provider
func RegisterProvider(provider Provider) {
	injector.Register(provider.Name(), provider)
}

// RegisterEncryptor register key encrypto
func RegisterEncryptor(name string, f Encryptor) {
	injector.Register(name, f)
}

// New create key
func New(driver string) (Key, error) {
	var provider Provider
	if !injector.Get(driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.New()
}

// From create key from exist key
func From(driver string, key Key) (Key, error) {
	toKey, err := New(driver)

	if err != nil {
		return nil, err
	}

	toKey.SetBytes(key.PriKey())

	return toKey, nil
}

// Recover recover public key from sig and hash
func Recover(driver string, sig []byte, hash []byte) ([]byte, error) {
	var provider RecoverableProvider
	if !injector.Get(driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.Recover(sig, hash)
}

// PublicKeyToAddress .
func PublicKeyToAddress(driver string, pubkey []byte) (string, error) {
	var provider Provider
	if !injector.Get(driver, &provider) {
		return "", xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.PublicKeyToAddress(pubkey)
}

// Verify .
func Verify(driver string, pubkey []byte, sig []byte, hash []byte) (bool, error) {
	var provider Provider
	if !injector.Get(driver, &provider) {
		return false, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.Verify(pubkey, sig, hash), nil
}

func getEncryptor(name string) (Encryptor, error) {
	var ef Encryptor
	if !injector.Get(name, &ef) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown encryptor %s", name)
	}

	return ef, nil
}

// Encrypt .
func Encrypt(encryptor string, key Key, attrs map[string]string, writer io.Writer) error {
	ec, err := getEncryptor(encryptor)

	if err != nil {
		return err
	}

	return ec.Encrypt(key, attrs, writer)
}

// Decrypt .
func Decrypt(encryptor string, key Key, attrs map[string]string, reader io.Reader) error {
	ec, err := getEncryptor(encryptor)

	if err != nil {
		return err
	}

	err = ec.Decrypt(key, attrs, reader)

	if err != nil {
		return xerrors.Wrapf(err, "decrypt with encryptor %s failed", encryptor)
	}

	return nil
}
