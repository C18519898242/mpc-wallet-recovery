package recovery

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Ed25519PublicContribution is a node's public contribution, or the aggregate
// returned by CombineEd25519PublicContributions. Keys use Ed25519 point encoding.
type Ed25519PublicContribution struct {
	PublicKey [32]byte
	ChainCode [32]byte
}

// Ed25519Contribution is one node's DKG input. Keep Scalar on that node.
type Ed25519Contribution struct {
	Scalar [32]byte
	Public Ed25519PublicContribution
}

// Ed25519PrivateKey is the recovered master signing scalar in canonical
// little-endian form and its chain code. Scalar cannot be used as an Ed25519 seed.
type Ed25519PrivateKey struct {
	Scalar    [32]byte
	ChainCode [32]byte
}

// DeriveEd25519Contribution uses the Safeheron V2 Ed25519 master contribution
// derivation at alternative index zero.
func DeriveEd25519Contribution(mnemonic string) (Ed25519Contribution, error) {
	block, err := deriveMasterContribution(mnemonic, algorithmEdDSAEd25519)
	if err != nil {
		return Ed25519Contribution{}, err
	}
	defer clear(block[:])

	var wide [64]byte
	defer clear(wide[:])
	copy(wide[:32], block[:32])
	var scalar edwards25519.Scalar
	defer scalar.Set(edwards25519.NewScalar())
	// The left half is a little-endian integer reduced modulo the group order.
	_, _ = scalar.SetUniformBytes(wide[:])
	if scalar.Equal(edwards25519.NewScalar()) == 1 {
		return Ed25519Contribution{}, errors.New("zero Ed25519 contribution")
	}
	var contribution Ed25519Contribution
	copy(contribution.Scalar[:], scalar.Bytes())
	copy(contribution.Public.PublicKey[:], new(edwards25519.Point).ScalarBaseMult(&scalar).Bytes())
	copy(contribution.Public.ChainCode[:], block[32:])
	return contribution, nil
}

// VerifyEd25519Backup checks one mnemonic against the node's saved public contribution.
func VerifyEd25519Backup(mnemonic string, expected Ed25519PublicContribution) error {
	contribution, err := DeriveEd25519Contribution(mnemonic)
	if err != nil {
		return err
	}
	clear(contribution.Scalar[:])
	if contribution.Public != expected {
		return errors.New("mnemonic does not match the node's Ed25519 public contribution")
	}
	return nil
}

// CombineEd25519PublicContributions combines one authenticated contribution per
// participant. The V2 chain code shares are summed modulo 2^256.
func CombineEd25519PublicContributions(contributions [3]Ed25519PublicContribution) (Ed25519PublicContribution, error) {
	var wallet Ed25519PublicContribution
	identity := edwards25519.NewIdentityPoint()
	total := edwards25519.NewIdentityPoint()
	eight := edwards25519.NewScalar()
	var encodedEight [32]byte
	encodedEight[0] = 8
	_, _ = eight.SetCanonicalBytes(encodedEight[:])
	inverseEight := edwards25519.NewScalar().Invert(eight)
	seen := make(map[[32]byte]bool, len(contributions))
	for i, contribution := range contributions {
		point, err := new(edwards25519.Point).SetBytes(contribution.PublicKey[:])
		if err != nil || [32]byte(point.Bytes()) != contribution.PublicKey || point.Equal(identity) == 1 {
			return Ed25519PublicContribution{}, fmt.Errorf("contribution %d: invalid Ed25519 public key", i+1)
		}
		// Project to the prime-order subgroup and require the input to already be there.
		cleared := new(edwards25519.Point).MultByCofactor(point)
		if cleared.ScalarMult(inverseEight, cleared).Equal(point) != 1 {
			return Ed25519PublicContribution{}, fmt.Errorf("contribution %d: Ed25519 key is outside the prime-order subgroup", i+1)
		}
		if seen[contribution.PublicKey] {
			return Ed25519PublicContribution{}, errors.New("duplicate Ed25519 public contribution")
		}
		seen[contribution.PublicKey] = true
		total.Add(total, point)
		addChainCode(&wallet.ChainCode, contribution.ChainCode)
	}
	if total.Equal(identity) == 1 {
		return Ed25519PublicContribution{}, errors.New("aggregate Ed25519 public key is the identity")
	}
	copy(wallet.PublicKey[:], total.Bytes())
	return wallet, nil
}

// RecoverEd25519PrivateKey reconstructs the signing scalar offline and verifies
// it against the trusted public key and chain code recorded at wallet creation.
func RecoverEd25519PrivateKey(mnemonics [3]string, expected Ed25519PublicContribution) (Ed25519PrivateKey, error) {
	total := edwards25519.NewScalar()
	defer total.Set(edwards25519.NewScalar())
	var public [3]Ed25519PublicContribution
	for i, mnemonic := range mnemonics {
		contribution, err := DeriveEd25519Contribution(mnemonic)
		if err != nil {
			return Ed25519PrivateKey{}, fmt.Errorf("mnemonic %d: %w", i+1, err)
		}
		public[i] = contribution.Public
		var scalar edwards25519.Scalar
		_, _ = scalar.SetCanonicalBytes(contribution.Scalar[:])
		total.Add(total, &scalar)
		scalar.Set(edwards25519.NewScalar())
		clear(contribution.Scalar[:])
	}
	wallet, err := CombineEd25519PublicContributions(public)
	if err != nil {
		return Ed25519PrivateKey{}, err
	}
	if wallet != expected {
		return Ed25519PrivateKey{}, errors.New("mnemonics do not match the expected Ed25519 public key and chain code")
	}
	if [32]byte(new(edwards25519.Point).ScalarBaseMult(total).Bytes()) != expected.PublicKey {
		return Ed25519PrivateKey{}, errors.New("recovered scalar does not match the expected Ed25519 public key")
	}
	return Ed25519PrivateKey{Scalar: [32]byte(total.Bytes()), ChainCode: wallet.ChainCode}, nil
}
