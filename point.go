package ecdsa_tools

import (
	"errors"
	"math/big"
)

type Point struct {
	X, Y  *big.Int
	AtInf bool
	Curve *Curve
}

func NewPoint(x, y *big.Int, curve *Curve) (*Point, error) {
	p := &Point{X: x, Y: y, Curve: curve}

	if !p.OnCurve() {
		return nil, errors.New("point not on curve")
	}

	return p, nil
}

func (p *Point) OnCurve() bool {
	if p.AtInf {
		return true
	}

	lhs := new(big.Int)
	lhs.Exp(p.Y, big.NewInt(2), p.Curve.P)

	rhs := new(big.Int)
	rhs.Exp(p.X, big.NewInt(3), p.Curve.P)
	rhs.Add(rhs, big.NewInt(0).Mul(p.Curve.A, p.X))
	rhs.Add(rhs, p.Curve.B)
	rhs.Mod(rhs, p.Curve.P)

	return lhs.Cmp(rhs) == 0
}

func (p *Point) Equals(q *Point) bool {
	// TODO Should verify the curves are the same

	if p.AtInf && q.AtInf {
		return true
	} else if p.AtInf && !q.AtInf {
		return false
	} else if !p.AtInf && q.AtInf {
		return false
	} else {
		return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
	}
}

func (p *Point) IsNegation(q *Point) bool {
	// TODO Should verify the curves are the same

	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(new(big.Int).Neg(q.Y)) == 0
}

func (p *Point) Negate() *Point {
	// TODO This wasn't explicit in references but seems correct / natural
	if p.AtInf {
		return &Point{AtInf: true, Curve: p.Curve}
	}

	return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Curve: p.Curve}
}

func (p *Point) Add(q *Point) *Point {
	// TODO Should verify the curves are the same

	if p.AtInf && q.AtInf {
		return &Point{AtInf: true, Curve: p.Curve}
	} else if p.AtInf && !q.AtInf {
		return &Point{X: new(big.Int).Set(q.X), Y: new(big.Int).Set(q.Y), Curve: p.Curve}
	} else if !p.AtInf && q.AtInf {
		return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Curve: p.Curve}
	}

	// FIXME Call Double
	//if p.Equals(q) {
	//}

	if p.IsNegation(q) {
		return &Point{AtInf: true, Curve: p.Curve}
	}

	// This should not be possible (ie if p.x == q.x then p.y == -q.y)
	if p.X.Cmp(q.X) == 0 {
		panic(errors.New("points with same x but not negations"))
	}

	// FIXME STOPPED Write explicit steps in the README.md (involves modinv)
	//               Verify new point OnCurve
	//               Also write some tests around this
	return &Point{Curve: p.Curve}
}

// FIXME Implement Double, Mul/Multiply
