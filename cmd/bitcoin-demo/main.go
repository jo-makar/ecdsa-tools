package main

import (
	ecdsa "github.com/jo-makar/ecdsa-tools"

	"golang.org/x/crypto/ripemd160"

	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

func main() {
	table := []struct {
		privkey    string
		base58Addr string
	}{
		// From https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
		{
			"18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
			"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
		},

		// From https://privatekeys.pw
		{
			"74f0a07b86441a008ac179a308255343cbc1c325f9fdd0ed9fbadb40bd294b32",
			"1FZqHrYNTMLpJMUwiiPERGwSHZdewNWLPX",
		},
		{
			"a56b8931f3e515bf6ec223ce4be2b9ab396fbf26cf1132b45decbb8c4a2babaa",
			"1QK6LMCC583QJPpvgzQ4SSKJdtfkYPzTKR",
		},
		{
			"eb5010572cf15c436da40f624cc4c47e65178081a36d30a817d47d85eb45132e",
			"1HLgnekKKRdBQ7z2txxW5EHUGZt36cUHAR",
		},
		{
			"a1d709fc21fe7b56ed4f14acf23586dafee8449822741d1cdf2c15c6595004e7",
			"1MJAeep33PMC5kWRdH4KUjSk2MfWBwMDxi",
		},
		{
			"2f9cc588cba4f0dd7f92022c4795dedb0d62b8b9c0987e3d615f2c4b3762fa84",
			"1BcMWDJQz4iFiZ6GPvpVP7bqzi6qKFCMGg",
		},
		{
			"dd5f6cd50ea9995ad25d7481e3b45b10e6de8655bbfe295ec9c24ce34419e8e3",
			"1P1GtJvtiSY25CFRbXvXxDtdjygfHUbVUd",
		},
		{
			"2c5ef6ecc00442919671babe3e4a2963ee377b7a9a2ba22fd299a7c1ab6007b7",
			"13QRBvNYjAYF8b3YHbXJKsc3T6pgZ2MRMj",
		},
		{
			"fdc0cd4245259d04124168c22f84ad04a5aee435a330c0e716bf47cf095319fd",
			"1CiHaVULNUpqn22B5mV4Y6pw1rYPsSzE7R",
		},
		{
			"be6fed0077d17dd919e64047f318068757e98fbdcfa84eda01cf122fc46a6be6",
			"1FVkUAgDeosKyQeGfWHtHhhryBptaz3R7h",
		},
		{
			"15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
			"1Nhc1grLraxJbCiGLPryCtv2d3i7G4Y9md",
		},
	}

	for _, entry := range table {
		privkey, err := ecdsa.NewPrivKeyBitcoin(entry.privkey)
		if err != nil {
			panic(err)
		}

		// Verify pubkey = privkey * G
		pubkey := privkey.CalcPubKey()
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

		// Uncompressed public keys are prefixed with 04 followed by the x and y coordinates

		compressedPubkey := func(pubkey *ecdsa.PubKey) []byte {
			x := pubkey.E.X.Text(16)
			if len(x) > 64 {
				panic(errors.New("pubkey x coord too long"))
			}
			x = fmt.Sprintf("%064s", x)

			z := big.NewInt(1)
			z.And(z, pubkey.E.Y)
			yIsOdd := z.Cmp(big.NewInt(1)) == 0

			var s string
			if yIsOdd {
				s = fmt.Sprintf("03%s", x)
			} else {
				s = fmt.Sprintf("02%s", x)
			}

			b, err := hex.DecodeString(s)
			if err != nil {
				panic(err)
			}
			return b
		}

		sha256Sum := func(data []byte) []byte {
			sum := sha256.Sum256(data)
			return sum[:]
		}

		ripemd160Sum := func(data []byte) []byte {
			h := ripemd160.New()
			h.Write(data)
			sum := h.Sum(nil)
			return sum[:]
		}

		hash := ripemd160Sum(sha256Sum(compressedPubkey(pubkey)))

		// Prepend network id byte (0x00 mainnet, 0x6f testnet)
		hash = append([]byte{0x00}, hash...)

		checksum := sha256Sum(sha256Sum(hash))
		addr := append(hash, checksum[0:4]...)

		base58Encode := func(data []byte) string {
			const encoding = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

			var buf string

			x := new(big.Int)
			x.SetBytes(data)

			for x.Cmp(big.NewInt(0)) == 1 {
				r := new(big.Int)
				x.QuoRem(x, big.NewInt(58), r)

				buf = string(encoding[r.Uint64()]) + buf
			}

			// Prepend the first encoded byte for each leading zero
			for i := 0; i < len(data) && data[i] == 0; i++ {
				buf = string(encoding[0]) + buf
			}

			return buf
		}

		base58Addr := base58Encode(addr)
		fmt.Printf("%s\n", base58Addr)
		if base58Addr != entry.base58Addr {
			panic(fmt.Errorf("mismatch %s (expected %s)", base58Addr, entry.base58Addr))
		}
	}
}
