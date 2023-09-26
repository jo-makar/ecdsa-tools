package ecdsa_tools

import (
	"errors"
	"math/big"
	"slices"
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
	if p == q {
		return true
	}

	if !p.Curve.Equals(q.Curve) {
		return false
	}

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
	if !p.Curve.Equals(q.Curve) {
		panic(errors.New("points not on same curve"))
	}

	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(new(big.Int).Neg(q.Y)) == 0
}

func (p *Point) Negate() *Point {
	// TODO This wasn't explicit in references but seems correct / natural
	if p.AtInf {
		return &Point{AtInf: true, Curve: p.Curve}
	}

	q := &Point{
		X:     new(big.Int).Set(p.X),
		Y:     new(big.Int).Neg(p.Y),
		Curve: p.Curve,
	}

	if !q.OnCurve() {
		panic(errors.New("negated point not on curve"))
	}

	return q
}

func (p *Point) Add(q *Point) *Point {
	if !p.Curve.Equals(q.Curve) {
		panic(errors.New("points not on same curve"))
	}

	if p.AtInf && q.AtInf {
		return &Point{AtInf: true, Curve: p.Curve}
	} else if p.AtInf && !q.AtInf {
		return &Point{X: new(big.Int).Set(q.X), Y: new(big.Int).Set(q.Y), Curve: p.Curve}
	} else if !p.AtInf && q.AtInf {
		return &Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y), Curve: p.Curve}
	}

	if p.Equals(q) {
		return p.Double()
	}

	if p.IsNegation(q) {
		return &Point{AtInf: true, Curve: p.Curve}
	}

	// This should not be possible (ie if p.x == q.x then p.y == -q.y)
	if p.X.Cmp(q.X) == 0 {
		panic(errors.New("points with same x but not negations"))
	}

	lambda := new(big.Int)
	lambda.Sub(q.X, p.X)
	lambda.ModInverse(lambda, p.Curve.P)
	lambda.Mul(lambda, new(big.Int).Sub(q.Y, p.Y))
	lambda.Mod(lambda, p.Curve.P)

	x := new(big.Int)
	x.Exp(lambda, big.NewInt(2), p.Curve.P)
	x.Sub(x, p.X)
	x.Sub(x, q.X)
	x.Mod(x, p.Curve.P)

	y := new(big.Int)
	y.Mul(lambda, new(big.Int).Sub(p.X, x))
	y.Sub(y, p.Y)
	y.Mod(y, p.Curve.P)

	r := &Point{X: x, Y: y, Curve: p.Curve}

	if !r.OnCurve() {
		panic(errors.New("added point not on curve"))
	}

	return r
}

func (p *Point) Double() *Point {
	if p.AtInf {
		return &Point{AtInf: true, Curve: p.Curve}
	}

	lambda := new(big.Int)
	{
		left := new(big.Int)
		left.Exp(p.X, big.NewInt(2), p.Curve.P)
		left.Mul(left, big.NewInt(3))
		left.Add(left, p.Curve.A)

		right := new(big.Int)
		right.Mul(big.NewInt(2), p.Y)
		right.ModInverse(right, p.Curve.P)

		lambda.Mul(left, right)
		lambda.Mod(lambda, p.Curve.P)
	}

	x := new(big.Int)
	x.Exp(lambda, big.NewInt(2), p.Curve.P)
	x.Sub(x, p.X)
	x.Sub(x, p.X)
	x.Mod(x, p.Curve.P)

	y := new(big.Int)
	y.Mul(lambda, new(big.Int).Sub(p.X, x))
	y.Sub(y, p.Y)
	y.Mod(y, p.Curve.P)

	q := &Point{X: x, Y: y, Curve: p.Curve}

	if !q.OnCurve() {
		panic(errors.New("added point not on curve"))
	}

	return q
}

func (p *Point) Multiply(k *big.Int) *Point {
	if k.Cmp(big.NewInt(0)) != 1 {
		panic(errors.New("multiply by k<1"))
	}
	// TODO What is multiplication by zero, the point at infinity?
	//      What is multiplcation by a negative number, multipled negation if k is odd?

	if p.AtInf {
		return &Point{AtInf: true, Curve: p.Curve}
	}

	cache := map[string]*Point{
		big.NewInt(1).String(): &Point{
			X:     new(big.Int).Set(p.X),
			Y:     new(big.Int).Set(p.Y),
			Curve: p.Curve,
		},
	}
	keys := []*big.Int{big.NewInt(1)}

	// Build the cache of (point) factors
	{
		i := big.NewInt(1)
		q := cache[i.String()]
		for {
			i.Mul(i, big.NewInt(2))
			if i.Cmp(k) == 1 { // i > k
				break
			}

			q = q.Double()
			cache[i.String()] = q
			keys = append(keys, new(big.Int).Set(i))
		}

		slices.Reverse(keys)
	}

	// Factor k using the cache
	i := big.NewInt(1)
	q := cache[i.String()]
	for {
		for _, j := range keys {
			if new(big.Int).Add(i, j).Cmp(k) == 1 {
				continue
			}

			q = q.Add(cache[j.String()])
			i.Add(i, j)

			// Check for the largest factor each iteration
			break
		}

		if i.Cmp(k) == 0 {
			break
		}
	}

	if !q.OnCurve() {
		panic(errors.New("multiplied point not on curve"))
	}

	return q
}
