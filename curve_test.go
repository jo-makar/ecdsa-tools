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
		g := &Point{X: curve.Gx, Y: curve.Gy, Curve: curve}
		if !g.OnCurve() {
			t.Errorf("%s: g not on curve", name)
		}

		// Verify n * G = O (point at infinity)

		multiplyGByN := func(g *Point, n *big.Int) (err error) {
			defer func() {
				if r := recover(); r != nil {
					if e, ok := r.(error); ok {
						err = e
					}
				}
			}()

			g.Multiply(n)
			return
		}

		if err := multiplyGByN(g, curve.N); err != nil {
			if errMsg := err.Error(); errMsg != "multiplied point not on curve" {
				t.Errorf("%s: n * g ?= o: %s", name, errMsg)
			}
		} else {
			t.Errorf("%s: n * g != o", name)
		}
	}
}
