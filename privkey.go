package ecdsa_tools

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"slices"
	"strings"
)

type PrivKey struct {
	D     *big.Int // Private key
	Curve *Curve
}

func NewRandomPrivKeyViaOpenSSL(curve string) (*PrivKey, error) {
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	encodedPrivKey, err := execStdout("", "openssl", "ecparam", "-name", curve, "-genkey")
	if err != nil {
		return nil, err
	}

	decodedPrivKey, err := execStdout(encodedPrivKey, "openssl", "ec", "-text", "-noout")
	if err != nil {
		return nil, err
	}

	decodedPrivKeyLines := strings.Split(decodedPrivKey, "\n")

	hexPrivKey, err := extractHexKey(decodedPrivKeyLines, "priv:")
	if err != nil {
		return nil, err
	}

	hexPubKey, err := extractHexKey(decodedPrivKeyLines, "pub:")
	if err != nil {
		return nil, err
	}

	privkey := new(big.Int)
	if _, ok := privkey.SetString(hexPrivKey, 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	if len(hexPubKey) != 130 || hexPubKey[0:2] != "04" {
		return nil, errors.New("unexpected pubkey format")
	}

	c := curves[curve]
	pubkey := &Point{X: new(big.Int), Y: new(big.Int), Curve: c}
	if _, ok := pubkey.X.SetString(hexPubKey[2:2+64], 16); !ok {
		return nil, errors.New("invalid hex value")
	}
	if _, ok := pubkey.Y.SetString(hexPubKey[2+64:2+64+64], 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	if !pubkey.OnCurve() {
		return nil, errors.New("pubkey not on curve")
	}

	// Verify pubkey = privkey * G
	g := &Point{X: c.Gx, Y: c.Gy, Curve: c}
	if !pubkey.Equals(g.Multiply(privkey)) {
		return nil, errors.New("pubkey privkey mismatch")
	}

	return &PrivKey{D: privkey, Curve: c}, nil
}

func NewPrivKeyViaOpenSSLFile(privKeyPath string) (*PrivKey, error) {
	decodedPrivKey, err := execStdout("", "openssl", "ec", "-text", "-noout", "-in", privKeyPath)
	if err != nil {
		return nil, err
	}

	decodedPrivKeyLines := strings.Split(decodedPrivKey, "\n")

	curve, err := extractField(decodedPrivKeyLines, "ASN1 OID:")
	if err != nil {
		return nil, err
	}
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	hexPrivKey, err := extractHexKey(decodedPrivKeyLines, "priv:")
	if err != nil {
		return nil, err
	}

	hexPubKey, err := extractHexKey(decodedPrivKeyLines, "pub:")
	if err != nil {
		return nil, err
	}

	privkey := new(big.Int)
	if _, ok := privkey.SetString(hexPrivKey, 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	if len(hexPubKey) != 130 || hexPubKey[0:2] != "04" {
		return nil, errors.New("unexpected pubkey format")
	}

	c := curves[curve]
	pubkey := &Point{X: new(big.Int), Y: new(big.Int), Curve: c}
	if _, ok := pubkey.X.SetString(hexPubKey[2:2+64], 16); !ok {
		return nil, errors.New("invalid hex value")
	}
	if _, ok := pubkey.Y.SetString(hexPubKey[2+64:2+64+64], 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	if !pubkey.OnCurve() {
		return nil, errors.New("pubkey not on curve")
	}

	// Verify pubkey = privkey * G
	g := &Point{X: c.Gx, Y: c.Gy, Curve: c}
	if !pubkey.Equals(g.Multiply(privkey)) {
		return nil, errors.New("pubkey privkey mismatch")
	}

	return &PrivKey{D: privkey, Curve: c}, nil
}

func NewRandomPrivKeyViaStdLib(curve string) (*PrivKey, error) {
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	return nil, errors.New("TODO implement using crypto/ecdsa.GenerateKey")
}

func NewRandomPrivKeyBitcoin() (*PrivKey, error) {
	curve := curves["secp256k1"]

	d, err := rand.Int(rand.Reader, curve.N)
	if err != nil {
		return nil, err
	}

	// rand.Int returns [0, N) so the first check may occur
	if big.NewInt(1).Cmp(d) == 1 { // 1 > d
		return nil, errors.New("invalid privkey value")
	}
	if d.Cmp(curve.N) >= 0 { // d >= curve.N
		return nil, errors.New("invalid privkey value")
	}

	privkey := PrivKey{D: d, Curve: curve}

	pubkey := privkey.CalcPubKey()
	if !pubkey.E.OnCurve() {
		return nil, errors.New("pubkey not on curve")
	}

	return &privkey, nil
}

func NewPrivKeyBitcoin(privKey string) (*PrivKey, error) {
	curve := curves["secp256k1"]

	d := new(big.Int)
	if _, ok := d.SetString(privKey, 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	if big.NewInt(1).Cmp(d) == 1 { // 1 > d
		return nil, errors.New("invalid privkey value")
	}
	if d.Cmp(curve.N) >= 0 { // d >= curve.N
		return nil, errors.New("invalid privkey value")
	}

	privkey := PrivKey{D: d, Curve: curve}

	pubkey := privkey.CalcPubKey()
	if !pubkey.E.OnCurve() {
		return nil, errors.New("pubkey not on curve")
	}

	return &privkey, nil
}

func NewRandomPrivKeyEthereum() (*PrivKey, error) {
	return nil, errors.New("TODO implement")
}

func NewPrivKeyEthereum(privKey string) (*PrivKey, error) {
	return nil, errors.New("TODO implement")
}

func (p *PrivKey) CalcPubKey() *PubKey {
	g := &Point{X: p.Curve.Gx, Y: p.Curve.Gy, Curve: p.Curve}
	return &PubKey{E: g.Multiply(p.D), Curve: p.Curve}
}

func execStdout(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout strings.Builder
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

func extractHexKey(lines []string, prefix string) (string, error) {
	prefixIndex := slices.Index(lines, prefix)
	if prefixIndex == -1 {
		return "", fmt.Errorf("prefix %s not found", prefix)
	}

	var hexKey strings.Builder
	for i := prefixIndex + 1; i < len(lines) && strings.HasPrefix(lines[i], " "); i++ {
		hexKey.WriteString(strings.TrimSpace(lines[i]))
	}
	if hexKey.Len() == 0 {
		return "", fmt.Errorf("no lines following prefix %s", prefix)
	}

	return strings.ReplaceAll(hexKey.String(), ":", ""), nil
}

func extractField(lines []string, prefix string) (string, error) {
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):]), nil
		}
	}
	return "", fmt.Errorf("prefix %s not found", prefix)
}

func (p *PrivKey) Sign(msg []byte, hashFunc func([]byte) []byte) (*big.Int, *big.Int) {
	n := p.Curve.N
	g := &Point{X: p.Curve.Gx, Y: p.Curve.Gy, Curve: p.Curve}

	hash := hashFunc(msg)
	h := new(big.Int).SetBytes(hash)

	l := n.BitLen()
	if len(hash)*8 > l {
		h.Rsh(h, uint(len(hash)*8-l))
	}

	var r, s *big.Int
	for {
		// Generate a random integer k in the range [1, n-1]
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(1)))
		if err != nil {
			panic(err)
		}
		k.Add(k, big.NewInt(1))

		q := g.Multiply(k)

		r = new(big.Int).Mod(q.X, n)
		if r.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		if r.Sign() == -1 {
			r.Neg(r)
			r.Mod(r, n)
		}

		left := new(big.Int).ModInverse(k, n)
		right := new(big.Int).Mul(r, p.D)
		right.Add(right, h)
		s = new(big.Int).Mul(left, right)
		s.Mod(s, n)
		if s.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		if s.Sign() == -1 {
			s.Neg(s)
			s.Mod(s, n)
		}

		break
	}

	return r, s
}
