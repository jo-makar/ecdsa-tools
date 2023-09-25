package ecdsa_tools

import (
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	curve := &Curve{
		P: big.NewInt(7),
		A: big.NewInt(3),
		B: big.NewInt(4),
	}

	p := &Point{
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
		Curve: curve,
	}

	q := &Point{
		X:     big.NewInt(2),
		Y:     big.NewInt(5),
		Curve: curve,
	}

	if !p.OnCurve() {
		t.Errorf("point not on curve")
	}
	if !q.OnCurve() {
		t.Errorf("point not on curve")
	}

	r := p.Add(q)
	if !r.OnCurve() {
		t.Errorf("result not on curve")
	}

	if r.X.Cmp(big.NewInt(6)) != 0 || r.Y.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("unexpected result")
	}
}

func TestAddNegation(t *testing.T) {
	curve := &Curve{
		P: big.NewInt(7),
		A: big.NewInt(3),
		B: big.NewInt(4),
	}

	p := &Point{
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
		Curve: curve,
	}

	q := p.Negate()

	if !p.OnCurve() {
		t.Errorf("point not on curve")
	}
	if !q.OnCurve() {
		t.Errorf("negated point not on curve")
	}

	r := p.Add(q)
	if !r.OnCurve() {
		t.Errorf("result not on curve")
	}

	if !r.AtInf {
		t.Errorf("unexpected result")
	}
}
