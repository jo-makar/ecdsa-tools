package ecdsa_tools

import (
	"math/big"
	"testing"
)

func TestCurves(t *testing.T) {
	for name, curve := range curves {
		// Verify n < p
		if curve.N.Cmp(curve.P) != -1 {
			t.Errorf("%s: n >= p", name)
		}

		// Verify (4a^3 + 27b^2) % p != 0 (excludes singular curves)

		v := new(big.Int)
		v.Exp(curve.A, big.NewInt(3), curve.P)
		v.Mul(v, big.NewInt(4))

		w := new(big.Int)
		w.Exp(curve.B, big.NewInt(2), curve.P)
		w.Mul(w, big.NewInt(27))

		v.Add(v, w)
		v.Mod(v, curve.P)

		if v.Cmp(big.NewInt(0)) == 0 {
			t.Errorf("%s: singular curve", name)
		}

		// Verify G is a point on the curve
		if !OnCurve(&curve.G, curve) {
			t.Errorf("%s: G not on curve", name)
		}
	}
}
