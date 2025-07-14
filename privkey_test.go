package ecdsa_tools

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

type testRandReader struct {
	state *big.Int
}

func (t testRandReader) Read(b []byte) (int, error) {
	if len(b) != 32 {
		panic(errors.New("expected 32 byte read"))
	}
	t.state.FillBytes(b)
	return len(b), nil
}

func TestSign(t *testing.T) {
	strToBigInt := func(s string) *big.Int {
		rv, ok := new(big.Int).SetString(s, 0)
		if !ok {
			t.Fatal("invalid string")
		}
		return rv
	}

	// Random example from https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/ecdsa/
	expectedZ := strToBigInt("0xde2d515297cad600f0365ef2be0f6d7e2ea3e757c7a9c8b3cdf49d8483670b1c")
	k := new(big.Int).Sub(strToBigInt("0x93001ea19e5261a5b00428ec478d49d11df2e0b1ac5378e507e3c6c1359e0724"), big.NewInt(1))
	d := strToBigInt("0xd9a4b9a99984eadea545b42efe7cd1eb101d2e55b30d35eb7a79fc216c087c57")
	expectedR := strToBigInt("89383775124345383949639009137714586387472647985584917903906909455303659871882")
	expectedSLow := strToBigInt("7439227374782059477889960317890800744771556402344980569214821196768403835101")
	expectedSHigh := strToBigInt("108352861862534135945681024690797107108066007876729923813390341944749757659236")

	origRandReader := rand.Reader
	rand.Reader = testRandReader{state: k}
	defer func() { rand.Reader = origRandReader }()

	privkey := &PrivKey{D: d, Curve: curves["secp256k1"]}

	msgBytes := []byte("Message for ECDSA signing")
	hashFunc := func(data []byte) []byte {
		rv := sha256.Sum256(data)
		return rv[:]
	}

	z := new(big.Int).SetBytes(hashFunc(msgBytes))
	if z.Cmp(expectedZ) != 0 {
		t.Fatalf("expected z to be %x, got %x", expectedZ, z)
	}

	r, s := privkey.Sign(msgBytes, hashFunc)

	if r.Cmp(expectedR) != 0 {
		t.Errorf("expected r to be %x, got %x", expectedR, r)
	}
	if s.Cmp(expectedSLow) != 0 && s.Cmp(expectedSHigh) != 0 {
		t.Errorf("expected s to be %x or %x, got %x", expectedSLow, expectedSHigh, s)
	}
}
