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
	Curve *Curve
	D     *big.Int // Private key
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

	d := new(big.Int)
	if _, ok := d.SetString(hexPrivKey, 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	pubkey := new(big.Int)
	if _, ok := pubkey.SetString(hexPubKey, 16); !ok {
		return nil, errors.New("invalid hex value")
	}

	// Verify pubkey = privkey * G
	// FIXME STOPPED
	fmt.Printf("0x%s\n", d.Text(16))
	fmt.Printf("0x%s\n", pubkey.Text(16))

	return nil, nil

	// FIXME Include a function to derive the PubKey from the PrivKey instance
}

func NewPrivKeyStdLib(curve string) (*PrivKey, error) {
	if !slices.Contains(supportedCurves, curve) {
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	// FIXME STOPPED
	return nil, nil
}

func NewPrivKeyBitcoin() (*PrivKey, error) {
	// FIXME STOPPED
	return nil, nil
}

func NewPrivKeyEthereum() (*PrivKey, error) {
	// FIXME STOPPED
	return nil, nil
}
