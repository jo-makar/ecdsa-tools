package ecdsa_tools

import (
	"errors"
	"math/big"
)

type Point struct {
	X, Y  *big.Int
	AtInf bool
}

func NewPoint(x, y *big.Int, curve *Curve) (*Point, error) {
	point := &Point{X: x, Y: y}

	if !OnCurve(point, curve) {
		return nil, errors.New("point not on curve")
	}

	return point, nil
}

func OnCurve(p *Point, c *Curve) bool {
	lhs := new(big.Int)
	lhs.Exp(p.Y, big.NewInt(2), c.P)

	rhs := new(big.Int)
	rhs.Exp(p.X, big.NewInt(3), c.P)
	rhs.Add(rhs, big.NewInt(0).Mul(c.A, p.X))
	rhs.Add(rhs, c.B)
	rhs.Mod(rhs, c.P)

	return lhs.Cmp(rhs) == 0
}

func (p *Point) Equal(q *Point) bool {
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
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(new(big.Int).Neg(q.Y)) == 0
}

func (p *Point) Negate() *Point {
	// TODO This wasn't explicit in references but seems correct / natural
	if p.AtInf {
		return &Point{AtInf: true}
	}

	return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}
}

func (p *Point) Add(q *Point) *Point {
	if p.AtInf && q.AtInf {
		return &Point{AtInf: true}
	} else if p.AtInf && !q.AtInf {
		return &Point{AtInf: true}
	} else if !p.AtInf && q.AtInf {
		return &Point{AtInf: true}
	}

	if p.IsNegation(q) {
		return &Point{AtInf: true}
	}

	// This should not be possible (ie if p.x == q.x then p.y == -q.y)
	if p.X.Cmp(q.X) == 0 {
		panic(errors.New("points with same x but not negations"))
	}

	// FIXME STOPPED Write explicit steps in the README.md
	//               Also write some tests around this
	return &Point{}
}

// FIXME Implement Double, Mul/Multiply
