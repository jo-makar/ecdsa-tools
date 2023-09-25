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

func TestDouble(t *testing.T) {
	curve := &Curve{
		P: big.NewInt(7),
		A: big.NewInt(3),
		B: big.NewInt(4),
	}

	p := &Point{
		X:     big.NewInt(2),
		Y:     big.NewInt(2),
		Curve: curve,
	}

	if !p.OnCurve() {
		t.Errorf("point not on curve")
	}

	q := p.Double()
	if !q.OnCurve() {
		t.Errorf("result not on curve")
	}

	if q.X.Cmp(big.NewInt(0)) != 0 || q.Y.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("unexpected result")
	}
}

func TestAddDouble(t *testing.T) {
	curve := &Curve{
		P: big.NewInt(7),
		A: big.NewInt(3),
		B: big.NewInt(4),
	}

	p := &Point{
		X:     big.NewInt(2),
		Y:     big.NewInt(2),
		Curve: curve,
	}

	if !p.OnCurve() {
		t.Errorf("point not on curve")
	}

	q := p.Add(p)
	if !q.OnCurve() {
		t.Errorf("result not on curve")
	}

	if q.X.Cmp(big.NewInt(0)) != 0 || q.Y.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("unexpected result")
	}
}

func TestMultiply(t *testing.T) {
	curve := &Curve{
		P: big.NewInt(17),
		A: big.NewInt(0),
		B: big.NewInt(7),
	}

	p := &Point{
		X:     big.NewInt(15),
		Y:     big.NewInt(13),
		Curve: curve,
	}

	if !p.OnCurve() {
		t.Errorf("point not on curve")
	}

	q := p.Multiply(big.NewInt(6))
	if !q.OnCurve() {
		t.Errorf("result not on curve")
	}

	if q.X.Cmp(big.NewInt(5)) != 0 || q.Y.Cmp(big.NewInt(8)) != 0 {
		t.Errorf("unexpected result")
	}
}
