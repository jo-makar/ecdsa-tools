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

func (p *PubKey) Verify(r, s *big.Int, msg []byte, hashFunc func([]byte) []byte) bool {
	n := p.Curve.N
	g := &Point{X: p.Curve.Gx, Y: p.Curve.Gy, Curve: p.Curve}

	if p.E.AtInf || !p.E.OnCurve() {
		return false
	}

	// Verify n * E = O (point at infinity)

	multiplyEByN := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(error); ok {
					err = e
				}
			}
		}()

		p.E.Multiply(n)
		return
	}

	if err := multiplyEByN(); err != nil {
		if errMsg := err.Error(); errMsg != "multiplied point not on curve" {
			return false
		}
	} else {
		return false
	}

	for _, v := range []*big.Int{r, s} {
		if v.Cmp(big.NewInt(0)) != 1 || v.Cmp(n) != -1 {
			return false
		}
	}

	hash := hashFunc(msg)
	h := new(big.Int).SetBytes(hash)

	l := n.BitLen()
	if len(hash)*8 > l {
		h.Rsh(h, uint(len(hash)*8-l))
	}

	w := new(big.Int).ModInverse(s, n)
	u := new(big.Int).Mul(h, w)
	u.Mod(u, n)
	v := new(big.Int).Mul(r, w)
	v.Mod(v, n)

	q := g.Multiply(u).Add(p.E.Multiply(v))
	if q.AtInf {
		return false
	}

	x := new(big.Int).Mod(q.X, n)
	if x.Sign() == -1 {
		x.Neg(x)
		x.Mod(x, n)
	}

	return r.Cmp(x) == 0
}
