package main

import (
	ecdsa "github.com/jo-makar/ecdsa-tools"

	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
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

	var r, s *big.Int
	for {
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(1)))
		if err != nil {
			panic(err)
		}
		k.Add(k, big.NewInt(1))

		g := &ecdsa.Point{X: privkey.Curve.Gx, Y: privkey.Curve.Gy, Curve: privkey.Curve}
		p := g.Multiply(k)

		r = new(big.Int).Mod(p.X, n)
		if r.Cmp(big.NewInt(0)) == 0 {
			fmt.Printf("choosing another k\n")
			continue
		}
		if r.Sign() == -1 {
			r.Neg(r)
			r.Mod(r, n)
		}

		left := new(big.Int).ModInverse(k, n)
		right := new(big.Int).Mul(r, privkey.D)
		right.Add(right, h)
		s = new(big.Int).Mul(left, right)
		s.Mod(s, n)
		if s.Cmp(big.NewInt(0)) == 0 {
			fmt.Printf("choosing another k\n")
			continue
		}
		if s.Sign() == -1 {
			s.Neg(s)
			s.Mod(s, n)
		}

		break
	}

	//
	// Signature ASN.1 marshalling
	//

	signature := []*big.Int{r, s}
	encodedSignature, err := asn1.Marshal(signature)
	if err != nil {
		panic(err)
	}

	//
	// Signature verification
	//

	execStdout := func(stdin []byte, name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)

		cmd.Stdin = bytes.NewBuffer(stdin)

		var stdout strings.Builder
		cmd.Stdout = &stdout

		if err := cmd.Run(); err != nil {
			return "", err
		}
		return stdout.String(), nil
	}

	output, err := execStdout(encodedSignature, "openssl", "dgst", "-sha256", "-verify", "pubkey.pem", "-signature", "/dev/stdin", FILE_PATH)
	if err != nil {
		panic(err)
	}

	if output != "Verified OK\n" {
		panic(errors.New("invalid signature"))
	} else {
		fmt.Printf("signature verified\n")
	}
}
