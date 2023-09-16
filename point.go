package ecdsa_tools

import (
	"math/big"
)

type Point struct {
	X, Y *big.Int
}
