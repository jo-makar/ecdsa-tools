# ecdsa-tools

Elliptic Curve Digital Signature Algorithm tools

## Notes

Elliptic curves are defined as (y^2) % p = (x^3 + ax + b) % p  
For which (4a^3 + 27b^2) % p != 0 (to exclude singular curves)

Domain parameters
- a and b are the equation constants above
- G is the generator point, a point on the curve above
- p is the (prime) congruence modulo above, ie lhs % p = rhs % p
- n is the number of possible points on the curve, note that n < p

Point addition  
Adding (the x, y components of) one point P to another point Q results in a point S  
If a line is drawn from P to Q it will result in a point R where R = -S

Point multiplication  
If P is added to P the result is 2P, similarly 2P + P is 3P

Trap door function  
Given R = kP where R and P are known, k cannot be determined  
This is the basis for ECDSA use in public-key cryptography  
Ie pubkey = privkey * G

## Documentation

<!-- FIXME Write a git hook to populate with `go doc -all` -->

```
package ecdsa_tools // import "github.com/jo-makar/ecdsa-tools"


TYPES

type Curve struct {
	P, A, B *big.Int // Elliptic curve definition: (y^2) % p = (x^3 + ax + b) % p
	G       Point    // Generator point (a point on the curve above)
	N       *big.Int // Number of possible points on the curve
}

type Point struct {
	X, Y *big.Int
}

type PrivKey struct {
	Curve *Curve
	D     *big.Int // Private key
}

func NewPrivKeyBitcoin() (*PrivKey, error)

func NewPrivKeyEthereum() (*PrivKey, error)

func NewPrivKeyOpenSSL(curve string) (*PrivKey, error)

func NewPrivKeyStdLib(curve string) (*PrivKey, error)
```

## cmd/demo/

Signature signing demo
