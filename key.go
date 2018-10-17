package key

import (
	"bytes"
	"errors"
	"io"

	"github.com/dynamicgo/xerrors"

	"github.com/dynamicgo/injector"
)

// Errors
var (
	ErrDriver = errors.New("unknown driver")
)

// Key blockchain key facade
type Key interface {
	Provider() Provider // key serivce driver
	Address() string    // address display string
	PriKey() []byte     // private key byte array
	PubKey() []byte     // public key byte array
}

// Provider the key service provider
type Provider interface {
	Name() string                                            // driver name
	New() (Key, error)                                       // create new key
	Encode(key Key, password string, writer io.Writer) error // encode key to an output stream
	Decode(password string, reader io.Reader) (Key, error)   // decode key from an input stream
}

// Register register provider
func Register(name string, provider Provider) {
	injector.Register(name, provider)
}

// New create key
func New(driver string) (Key, error) {
	var provider Provider
	if !injector.Get(driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.New()
}

// Decode decode .
func Decode(driver string, password string, reader io.Reader) (Key, error) {
	var provider Provider
	if !injector.Get(driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.Decode(password, reader)
}

// Encode encode key
func Encode(key Key, password string, writer io.Writer) error {
	return key.Provider().Encode(key, password, writer)
}

// EncodeToString .
func EncodeToString(key Key, password string) (string, error) {

	var buff bytes.Buffer

	if err := key.Provider().Encode(key, password, &buff); err != nil {
		return "", xerrors.Wrapf(err, "key provider %s decode error", key.Provider().Name())
	}

	return buff.String(), nil
}
