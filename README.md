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

### Elliptic curve arithmetic

Ref: <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication>

#### Point at infinity

The identity element, adding it to any point results in that point  
This including adding the identity element to itself

#### Point negation

Adding a point and its negation results in the point at infinity  
Negated points have the same x coordinate and negated y coordinate

#### Point addition

Adding (the x, y components of) one point P to another point Q results in a point S  
If a line is drawn from P to Q it will result in a point R where R = -S

P + Q = R  
(xp, yp) + (xq, yq) = (xr, yr)

lambda = ((yq - yp) / (xq - xp)) % p  
"Division" is via modular inverse  
Modular inverse: Find b such that (a * b) % m = 1  
lambda = ((yq - yp) * modinv(xq - xp, p)) % p

xr = (lambda^2 - xp - xq) % p  
yr = (lambda * (xp - xr) - yp) % p

#### Point doubling

As above but with

lambda = ((3 * xp^2 + a) / (2 * yp)) % p  
lambda = ((3 * xp^2 + a) * modinv(2 * yp, p)) % p

#### Point multiplication

If P is added to P the result is 2P, similarly 2P + P is 3P

#### Trap door function

Given R = kP where R and P are known, k cannot be determined  
This is the basis for ECDSA use in public-key cryptography  
Ie pubkey = privkey * G

## Documentation

<!-- go doc start -->
```
package ecdsa_tools // import "github.com/jo-makar/ecdsa-tools"


TYPES

type Curve struct {
	P, A, B *big.Int // Elliptic curve definition: (y^2) % p = (x^3 + ax + b) % p
	Gx, Gy  *big.Int // Generator point (a point on the curve above)
	N       *big.Int // Number of possible points on the curve
}

func (c *Curve) Equals(d *Curve) bool

type Point struct {
	X, Y  *big.Int
	AtInf bool
	Curve *Curve
}

func NewPoint(x, y *big.Int, curve *Curve) (*Point, error)

func (p *Point) Add(q *Point) *Point

func (p *Point) Double() *Point

func (p *Point) Equals(q *Point) bool

func (p *Point) IsNegation(q *Point) bool

func (p *Point) Multiply(k *big.Int) *Point

func (p *Point) Negate() *Point

func (p *Point) OnCurve() bool

type PrivKey struct {
	Curve *Curve
	D     *big.Int // Private key
}

func NewPrivKeyBitcoin() (*PrivKey, error)

func NewPrivKeyEthereum() (*PrivKey, error)

func NewPrivKeyOpenSSL(curve string) (*PrivKey, error)

func NewPrivKeyStdLib(curve string) (*PrivKey, error)

```
<!-- go doc end -->

## cmd/demo/

Signature signing demo
