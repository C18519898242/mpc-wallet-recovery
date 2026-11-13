package recovery_test

import (
	"testing"

	"github.com/C18519898242/mpc-wallet-recovery/recovery"
)

func TestSafeheronEd25519Vectors(t *testing.T) {
	var input struct {
		Parties [3]struct {
			ID       string `json:"party_id"`
			Mnemonic string
		}
	}
	type vector struct {
		ID        string `json:"party_id"`
		Scalar    string
		ChainCode string `json:"chain_code"`
		PublicKey string `json:"public_key"`
	}
	var expected struct {
		Source    string
		Algorithm string
		Parties   [3]vector
		Wallet    vector
	}
	readFixture(t, "bip39-mnemonics.json", &input)
	readFixture(t, "safeheron-ed25519-v2.json", &expected)
	if expected.Source != "@safeheron/master-key-derive@2.0.1" || expected.Algorithm != "EDDSA_ED25519" {
		t.Fatal("unexpected fixture provenance")
	}

	var words [3]string
	var public [3]recovery.Ed25519PublicContribution
	for i, node := range input.Parties {
		want := expected.Parties[i]
		if node.ID == "" || node.ID != want.ID {
			t.Fatal("unexpected fixture party")
		}
		words[i] = node.Mnemonic
		contribution, err := recovery.DeriveEd25519Contribution(node.Mnemonic)
		if err != nil {
			t.Fatal(err)
		}
		public[i] = contribution.Public
		checkHex(t, contribution.Scalar[:], want.Scalar)
		checkHex(t, public[i].PublicKey[:], want.PublicKey)
		checkHex(t, public[i].ChainCode[:], want.ChainCode)
		if err := recovery.VerifyEd25519Backup(node.Mnemonic, public[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := recovery.VerifyEd25519Backup(words[0], public[1]); err == nil {
		t.Fatal("accepted another node's backup")
	}
	wallet, err := recovery.CombineEd25519PublicContributions(public)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, wallet.PublicKey[:], expected.Wallet.PublicKey)
	checkHex(t, wallet.ChainCode[:], expected.Wallet.ChainCode)
	words[0], words[2] = words[2], words[0]
	key, err := recovery.RecoverEd25519PrivateKey(words, wallet)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, key.Scalar[:], expected.Wallet.Scalar)
	checkHex(t, key.ChainCode[:], expected.Wallet.ChainCode)

	wrong := wallet
	wrong.ChainCode[0] ^= 1
	if key, err := recovery.RecoverEd25519PrivateKey(words, wrong); err == nil || key != (recovery.Ed25519PrivateKey{}) {
		t.Fatal("returned secret with wrong chain code")
	}
	wrong = wallet
	wrong.PublicKey[0] ^= 1
	if _, err := recovery.RecoverEd25519PrivateKey(words, wrong); err == nil {
		t.Fatal("accepted wrong public key")
	}
	words[0] = words[1]
	if _, err := recovery.RecoverEd25519PrivateKey(words, wallet); err == nil {
		t.Fatal("accepted duplicate backup")
	}
	public[0].PublicKey = [32]byte{1}
	if _, err := recovery.CombineEd25519PublicContributions(public); err == nil {
		t.Fatal("accepted identity contribution")
	}
	public[0].PublicKey = [32]byte{} // Canonical point of order four.
	if _, err := recovery.CombineEd25519PublicContributions(public); err == nil {
		t.Fatal("accepted torsion point")
	}
}
