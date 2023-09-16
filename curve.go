package ecdsa_tools

import (
	"errors"
	"math/big"
)

type Curve struct {
	P, A, B *big.Int // Elliptic curve definition: (y^2) % p = (x^3 + ax + b) % p
	G       Point    // Generator point (a point on the curve above)
	N       *big.Int // Number of possible points on the curve
}

func newBigInt(s string) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(s, 0); !ok {
		panic(errors.New("invalid value"))
	}
	return i
}

var curves = map[string]*Curve{
	"prime256v1": {
		// https://neuromancer.sk/std/x962/prime256v1
		P: newBigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
		A: newBigInt("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
		B: newBigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
		G: Point{
			X: newBigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
			Y: newBigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
		},
		N: newBigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	},
	"secp256k1": {
		// https://neuromancer.sk/std/secg/secp256k1
		P: newBigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
		A: big.NewInt(0),
		B: big.NewInt(7),
		G: Point{
			X: newBigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
			Y: newBigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
		},
		N: newBigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
	},
}

var supportedCurves = func() []string {
	var rv []string
	for c := range curves {
		rv = append(rv, c)
	}
	return rv
}()
