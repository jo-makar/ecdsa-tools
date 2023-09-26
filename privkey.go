package ecdsa_tools

import (
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

func NewPrivKeyOpenSSL(curve string) (*PrivKey, error) {
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	execStdout := func(stdin string, name string, args ...string) (string, error) {
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

	encodedPrivKey, err := execStdout("", "openssl", "ecparam", "-name", curve, "-genkey")
	if err != nil {
		return nil, err
	}

	decodedPrivKey, err := execStdout(encodedPrivKey, "openssl", "ec", "-text", "-noout")
	if err != nil {
		return nil, err
	}

	decodedPrivKeyLines := strings.Split(decodedPrivKey, "\n")

	extractHexKey := func(lines []string, prefix string) (string, error) {
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

	// Verify pubkey = privkey * G
	g := &Point{X: c.Gx, Y: c.Gy, Curve: c}
	if !pubkey.Equals(g.Multiply(privkey)) {
		return nil, errors.New("pubkey privkey mismatch")
	}

	return &PrivKey{D: privkey, Curve: c}, nil
}

func NewPrivKeyStdLib(curve string) (*PrivKey, error) {
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	// FIXME Implement
	return nil, nil
}

func NewPrivKeyBitcoin() (*PrivKey, error) {
	// FIXME Implement
	return nil, nil
}

func NewPrivKeyEthereum() (*PrivKey, error) {
	// FIXME Implement
	return nil, nil
}

func (p *PrivKey) CalcPubKey() *PubKey {
	g := &Point{X: p.Curve.Gx, Y: p.Curve.Gy, Curve: p.Curve}
	return &PubKey{E: g.Multiply(p.D), Curve: p.Curve}
}
