# ecdsa-tools

Elliptic Curve Digital Signature Algorithm tools

Elliptic curves are defined as $y^2 \equiv x^3 + ax + b \pmod p$.
For which $(4a^3 + 27b^2) \bmod p \neq 0$ (to exclude singular curves).

These curves are symmetric about the x-axis.
A straight line can intersect the curve at a maximum of three points.

Domain parameters
- $a$ and $b$ are the equation constants above
- $G$ is the generator point, a point on the curve above
- $p$ is the (prime) congruence modulo above, ie $lhs \bmod p = rhs \bmod p$
- $n$ is the number of possible points on the curve, note that $n < p$

Note that $n * G = O$ (point at infinity).
This implies that $n * pubkey = O$ because $n * (privkey * G) = O$.

## Arithmetic

References
- <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication>
- <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>

### Point at infinity
The point at infinity is a special point that does not lie on the curve,
resulting from adding two points whose sum is not on the curve.
In addition it acts as an identity element, adding it to any point results in itself.

### Point negation
Adding a point and its negation results in the point at infinity.
Negated points have the same x coordinate and negated y coordinate.

### Point addition

Adding (the x, y components of) one point $P$ to another point $Q$ results in a point $S$.
If a line is drawn from $P$ to $Q$ it will result in a point $R$ where $R = -S$.

$P + Q = R$  
$(xp, yp) + (xq, yq) = (xr, yr)$

$\lambda = ((yq - yp) / (xq - xp)) \bmod p$  
"Division" is via modular inverse.  
Modular inverse: Find $b$ such that $(a * b) \bmod m = 1$  
$\lambda = ((yq - yp) * modinv(xq - xp, p)) \bmod p$

$xr = (\lambda^2 - xp - xq) \bmod p$  
$yr = (\lambda * (xp - xr) - yp) \bmod p$

### Point doubling
Same as point addition but with  
$\lambda = ((3 * xp^2 + a) / (2 * yp)) \bmod p$  
$\lambda = ((3 * xp^2 + a) * modinv(2 * yp, p)) \bmod p$

### Point multiplication

$nP = P + P + P + ... + P$

If $n$ is negative:  
$(-n)P = (-P) + (-P) + (-P) ... + (-P)$

If $n$ is zero then $nP$ is the point at infinity.

### Trap door function
Given $R = kP$ where $R$ and $P$ are known, $k$ cannot be determined.
This is the basis for ECDSA use in public-key cryptography, ie $pubkey = privkey * G$.

### Signature generation
- Let $L$ be the bit length of $n$
- Let $z$ be the leftmost $L$ bits of $hash(message)$
- Select a random integer $k$ in the range $[1, n-1]$
- Calculate $(x, y) = k * G$
- Calculte $r = x \bmod n$
  - If $r = 0$ then choose a different $k$
- Calculate $s = (k^-1 * (z + r * privkey)) \bmod n = (modinv(k, n) * (z + r * privkey)) \bmod n$
  - If $s = 0$ then choose a different $k$
- The signature is $(r, s)$
  - If $r$ or $s$ is negative make positive with %a = -a \bmod n%

### Signature verification
- Verify the $pubkey \neq O$ (point at infinity)
- Verify the $pubkey$ lies on the curve
- Verify $n * pubkey = O$
- Verify $r$ and $s$ are in the range $[1, n-1]$
- Let $L$ be the bit length of $n$
- Let $z$ be the leftmost $L$ bits of $hash(message)$
- Calculate $u = (z * s^-1) \bmod n = (z * modinv(s, n)) \bmod n$
- Calculate $v = (r * s^-1) \bmod n = (r * modinv(s, n)) \bmod n$
- Calculate $(x, y) = uG + v * pubkey$
  - If the point $(x, y) = O$ then the signature is invalid
- Verify $r = x \bmod n$

### Bitcoin addresses
A Bitcoin address is created by hashing a public key

### Ethereum signatures

References
- <https://ethereum.github.io/yellowpaper/paper.pdf>, Appendix F: Signing Transactions
- <https://eklitzke.org/bitcoin-transaction-malleability>
  - Bitcoin and Ethereum use the same Elliptic curve (secp256k1)

A signature is invalid unless:
- $0 < r < n$
- $0 < s < (n \texttt{>>} 1) + 1$
  - Restricted to the lower half to prevent transaction malleability
- $v$ is zero or one (often shifted to 27 or 28)
  - The lower (higher) value represents an even (odd) $y$

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
	D     *big.Int // Private key
	Curve *Curve
}

func NewPrivKeyBitcoin(privKey string) (*PrivKey, error)

func NewPrivKeyEthereum(privKey string) (*PrivKey, error)

func NewPrivKeyViaOpenSSLFile(privKeyPath string) (*PrivKey, error)

func NewRandomPrivKeyBitcoin() (*PrivKey, error)

func NewRandomPrivKeyEthereum() (*PrivKey, error)

func NewRandomPrivKeyViaOpenSSL(curve string) (*PrivKey, error)

func NewRandomPrivKeyViaStdLib(curve string) (*PrivKey, error)

func (p *PrivKey) CalcPubKey() *PubKey

type PubKey struct {
	E     *Point // Public key
	Curve *Curve
}

func NewPubKeyEthereum(address string) (*PubKey, error)

func NewPubKeyViaOpenSSLFile(pubKeyPath string) (*PubKey, error)

```
<!-- go doc end -->

## cmd/verify-demo/
OpenSSL signature verification demo

## cmd/sign-demo/
OpenSSL signature (generation) demo

## cmd/bitcoin-demo/
Bitcoin private key to address demo
