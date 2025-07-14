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

	var r, s *big.Int
	{
		bytes, err := os.ReadFile(FILE_PATH)
		if err != nil {
			panic(err)
		}

		hashFunc := func(data []byte) []byte {
			rv := sha256.Sum256(data)
			return rv[:]
		}
		r, s = privkey.Sign(bytes, hashFunc)
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
