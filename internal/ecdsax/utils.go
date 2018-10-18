package ecdsax

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/laplacenetwork/key/internal/secp256k1"
)

// PublicKeyBytes .
func PublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(secp256k1.SECP256K1(), pub.X, pub.Y)
}

// PrivateKeyBytes 。
func PrivateKeyBytes(priv *ecdsa.PrivateKey) (b []byte) {
	d := priv.D.Bytes()

	/* Pad D to 32 bytes */
	paddedd := append(bytes.Repeat([]byte{0x00}, 32-len(d)), d...)

	return paddedd
}

// BytesToPrivateKey 。
func BytesToPrivateKey(key []byte, curve elliptic.Curve) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(key)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(key)
	return priv
}
