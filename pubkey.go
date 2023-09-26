package ecdsa_tools

type PubKey struct {
	E     *Point // Public key
	Curve *Curve
}

func NewPubKeyBitcoin(address string) (*PrivKey, error) {
	// FIXME Implement
	return nil, nil
}

func NewPubKeyEthereum(address string) (*PrivKey, error) {
	// FIXME Implement
	return nil, nil
}
