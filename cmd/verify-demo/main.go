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

	data, err := os.ReadFile(FILE_PATH)
	if err != nil {
		panic(err)
	}

	hashFunc := func(data []byte) []byte {
		rv := sha256.Sum256(data)
		return rv[:]
	}

	if pubkey.Verify(r, s, data, hashFunc) {
		fmt.Printf("valid signature\n")
	} else {
		panic(errors.New("invalid signature"))
	}
}
