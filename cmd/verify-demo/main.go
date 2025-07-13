package main

import (
	ecdsa "github.com/jo-makar/ecdsa-tools"

	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
)

func main() {
	// openssl ecparam -name prime256v1 -genkey -out privkey.pem
	// openssl ec -in privkey.pem -pubout -out pubkey.pem

	const FILE_PATH = "README.md"

	privkey, err := ecdsa.NewPrivKeyViaOpenSSLFile("privkey.pem")
	if err != nil {
		panic(err)
	}

	pubkey, err := ecdsa.NewPubKeyViaOpenSSLFile("pubkey.pem")
	if err != nil {
		panic(err)
	}

	// Verify pubkey = privkey * G
	if !privkey.Curve.Equals(pubkey.Curve) {
		panic(errors.New("pubkey privkey curve mismatch"))
	}
	{
		c := privkey.Curve
		g := &ecdsa.Point{X: c.Gx, Y: c.Gy, Curve: c}
		if !pubkey.E.Equals(g.Multiply(privkey.D)) {
			panic(errors.New("pubkey privkey mismatch"))
		}
	}

	//
	// Signature generation
	//

	execStdout := func(name string, args ...string) ([]byte, error) {
		cmd := exec.Command(name, args...)

		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		if err := cmd.Run(); err != nil {
			return nil, err
		}
		return stdout.Bytes(), nil
	}

	encodedSignature, err := execStdout("openssl", "dgst", "-sha256", "-sign", "privkey.pem", FILE_PATH)
	if err != nil {
		panic(err)
	}

	//
	// Signature ASN.1 unmarshalling
	// ... | openssl asn1parse -inform der
	//

	var signature []*big.Int
	if rest, err := asn1.Unmarshal(encodedSignature, &signature); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		panic(errors.New("trailing bytes"))
	}
	if len(signature) != 2 {
		panic(errors.New("unexpected sequence length"))
	}

	r, s := signature[0], signature[1]

	//
	// Signature verification
	//

	n := pubkey.Curve.N

	h := new(big.Int)
	{
		fileBytes, err := os.ReadFile(FILE_PATH)
		if err != nil {
			panic(err)
		}

		fileHash := sha256.Sum256(fileBytes)
		h.SetBytes(fileHash[:])

		l := n.BitLen()
		if sha256.Size*8 > l {
			h.Rsh(h, uint(sha256.Size*8-l))
		}
	}

	if pubkey.E.AtInf {
		panic(errors.New("pubkey is point at infinity"))
	}
	if !pubkey.E.OnCurve() {
		panic(errors.New("pubkey not on curve"))
	}

	multiplyEByN := func(e *ecdsa.Point, n *big.Int) (err error) {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(error); ok {
					err = e
				}
			}
		}()

		e.Multiply(n)
		return
	}
	if err := multiplyEByN(pubkey.E, n); err != nil {
		if errMsg := err.Error(); errMsg != "multiplied point not on curve" {
			panic(fmt.Errorf("n * e ?= o: %s", errMsg))
		}
	} else {
		panic("n * e != o")
	}

	for _, v := range []*big.Int{r, s} {
		if v.Cmp(big.NewInt(0)) != 1 {
			panic(errors.New("v <= 0, invalid signature"))
		}
		if v.Cmp(n) != -1 {
			panic(errors.New("v >= n, invalid signature"))
		}
	}

	w := new(big.Int).ModInverse(s, n)
	u := new(big.Int).Mul(h, w)
	u.Mod(u, n)
	v := new(big.Int).Mul(r, w)
	v.Mod(v, n)

	{
		g := &ecdsa.Point{X: pubkey.Curve.Gx, Y: pubkey.Curve.Gy, Curve: pubkey.Curve}
		p := g.Multiply(u).Add(pubkey.E.Multiply(v))
		if p.AtInf {
			panic(errors.New("result is point at infinity"))
		}

		x := new(big.Int).Mod(p.X, n)
		if x.Sign() == -1 {
			x.Neg(x)
			x.Mod(x, n)
		}
		if r.Cmp(x) != 0 {
			panic(errors.New("invalid signature"))
		} else {
			fmt.Printf("valid signature\n")
		}
	}
}
