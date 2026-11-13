package recovery

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"
)

// CMPPublicContribution contains the data a node shares with the other nodes
// before starting a new wallet. Authenticate the sender and bind it to its node ID.
// Combining three contributions returns the wallet's compressed public key and chain code.
type CMPPublicContribution struct {
	PublicKey [33]byte
	ChainCode [32]byte
}

// CMPContribution contains one node's private input to cmp.ImportKey.
// Keep Scalar on that node and send only Public to the other nodes.
type CMPContribution struct {
	Scalar [32]byte
	Public CMPPublicContribution
}

// GenerateMnemonic creates a 24-word English BIP-39 phrase from 256 random bits.
// Each node generates and backs up its own phrase independently.
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	defer clear(entropy)
	return bip39.NewMnemonic(entropy)
}

// DeriveCMPContribution uses the Safeheron V2 secp256k1 master contribution
// derivation, starting with the BIP-39 entropy and alternative index zero.
func DeriveCMPContribution(mnemonic string) (CMPContribution, error) {
	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		return CMPContribution{}, errors.New("expected a 24-word BIP-39 mnemonic")
	}
	entropy, err := bip39.EntropyFromMnemonic(strings.Join(words, " "))
	if err != nil {
		return CMPContribution{}, errors.New("invalid BIP-39 mnemonic")
	}
	defer clear(entropy)

	block := hmacSHA512([]byte("MPC seed"), entropy)
	defer clear(block[:])
	// The four-byte fields encode master-key purpose, ECDSA/secp256k1,
	// and alternative index zero, respectively.
	for range 3 {
		var input [36]byte
		copy(input[:], block[32:])
		block = hmacSHA512(block[:32], input[:])
		clear(input[:])
	}

	var scalar secp256k1.ModNScalar
	defer scalar.Zero()
	scalar.SetByteSlice(block[:32]) // Reduce the HMAC output modulo the curve order.
	if scalar.IsZero() {
		return CMPContribution{}, errors.New("zero CMP contribution")
	}
	var contribution CMPContribution
	contribution.Scalar = scalar.Bytes()
	contribution.Public.PublicKey = cmpPublicKey(&scalar)
	copy(contribution.Public.ChainCode[:], block[32:])
	return contribution, nil
}

// CombineCMPPublicContributions computes the shared inputs to cmp.ImportKey.
// Supply exactly one authenticated contribution from each participant.
func CombineCMPPublicContributions(contributions [3]CMPPublicContribution) (CMPPublicContribution, error) {
	var wallet CMPPublicContribution
	var total secp256k1.JacobianPoint
	seen := make(map[[33]byte]bool, len(contributions))
	for i, contribution := range contributions {
		if contribution.PublicKey[0] != 2 && contribution.PublicKey[0] != 3 {
			return CMPPublicContribution{}, fmt.Errorf("contribution %d: expected a compressed secp256k1 public key", i+1)
		}
		point, err := secp256k1.ParsePubKey(contribution.PublicKey[:])
		if err != nil {
			return CMPPublicContribution{}, fmt.Errorf("contribution %d: invalid secp256k1 public key", i+1)
		}
		if seen[contribution.PublicKey] {
			return CMPPublicContribution{}, errors.New("duplicate CMP public contribution")
		}
		seen[contribution.PublicKey] = true

		var jacobian secp256k1.JacobianPoint
		point.AsJacobian(&jacobian)
		secp256k1.AddNonConst(&total, &jacobian, &total)
		// Sum big-endian chain codes modulo 2^256.
		var carry uint16
		for j := len(wallet.ChainCode) - 1; j >= 0; j-- {
			sum := uint16(wallet.ChainCode[j]) + uint16(contribution.ChainCode[j]) + carry
			wallet.ChainCode[j] = byte(sum)
			carry = sum >> 8
		}
	}
	if total.Z.IsZero() {
		return CMPPublicContribution{}, errors.New("aggregate CMP public key is the point at infinity")
	}
	total.ToAffine()
	copy(wallet.PublicKey[:], secp256k1.NewPublicKey(&total.X, &total.Y).SerializeCompressed())
	return wallet, nil
}

// RecoverCMPPrivateKey reconstructs the full signing key on an offline machine.
// expected must come from a trusted record made when the wallet was created.
func RecoverCMPPrivateKey(mnemonics [3]string, expected CMPPublicContribution) ([32]byte, error) {
	var total secp256k1.ModNScalar
	defer total.Zero()
	var public [3]CMPPublicContribution
	for i, mnemonic := range mnemonics {
		contribution, err := DeriveCMPContribution(mnemonic)
		if err != nil {
			return [32]byte{}, fmt.Errorf("mnemonic %d: %w", i+1, err)
		}
		public[i] = contribution.Public
		var scalar secp256k1.ModNScalar
		scalar.SetBytes(&contribution.Scalar)
		total.Add(&scalar)
		scalar.Zero()
		clear(contribution.Scalar[:])
	}
	wallet, err := CombineCMPPublicContributions(public)
	if err != nil {
		return [32]byte{}, err
	}
	if wallet != expected {
		return [32]byte{}, errors.New("mnemonics do not match the expected wallet public key and chain code")
	}
	return total.Bytes(), nil
}

func hmacSHA512(key, data []byte) (out [64]byte) {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	mac.Sum(out[:0])
	return out
}

func cmpPublicKey(scalar *secp256k1.ModNScalar) (out [33]byte) {
	key := secp256k1.NewPrivateKey(scalar)
	defer key.Zero()
	copy(out[:], key.PubKey().SerializeCompressed())
	return out
}
