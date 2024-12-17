package ecdsa_tools

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

type PubKey struct {
	E     *Point // Public key
	Curve *Curve
}

func NewPubKeyViaOpenSSLFile(pubKeyPath string) (*PubKey, error) {
	decodedPubKey, err := execStdout("", "openssl", "ec", "-text", "-noout", "-in", pubKeyPath, "-pubin")
	if err != nil {
		return nil, err
	}

	decodedPubKeyLines := strings.Split(decodedPubKey, "\n")

	curve, err := extractField(decodedPubKeyLines, "ASN1 OID:")
	if err != nil {
		return nil, err
	}
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	hexPubKey, err := extractHexKey(decodedPubKeyLines, "pub:")
	if err != nil {
		return nil, err
	}

	if len(hexPubKey) != 130 || hexPubKey[0:2] != "04" {
		return nil, errors.New("unexpected pubkey format")
	}

	c := curves[curve]
	pubkey := &Point{X: new(big.Int), Y: new(big.Int), Curve: c}
	if _, ok := pubkey.X.SetString(hexPubKey[2:2+64], 16); !ok {
		return nil, errors.New("invalid hex value")
	}
	if _, ok := pubkey.Y.SetString(hexPubKey[2+64:2+64+64], 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	if !pubkey.OnCurve() {
		return nil, errors.New("pubkey not on curve")
	}

	return &PubKey{E: pubkey, Curve: c}, nil
}

func NewPubKeyEthereum(address string) (*PubKey, error) {
	return nil, errors.New("TODO implement")
}
