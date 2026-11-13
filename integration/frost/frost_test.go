package integration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"os"
	"testing"

	"filippo.io/edwards25519"
	"github.com/C18519898242/mpc-wallet-recovery/recovery"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func TestFROSTBackup(t *testing.T) {
	data, err := os.ReadFile("../../testdata/bip39-mnemonics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Parties [3]struct{ Mnemonic string } }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var words [3]string
	var contributions [3]recovery.Ed25519Contribution
	var public [3]recovery.Ed25519PublicContribution
	for i, node := range fixture.Parties {
		words[i] = node.Mnemonic
		contributions[i], err = recovery.DeriveEd25519Contribution(node.Mnemonic)
		if err != nil {
			t.Fatal(err)
		}
		public[i] = contributions[i].Public
		if err := recovery.VerifyEd25519Backup(node.Mnemonic, public[i]); err != nil {
			t.Fatal(err)
		}
	}
	wallet, err := recovery.CombineEd25519PublicContributions(public)
	if err != nil {
		t.Fatal(err)
	}
	expected := ed25519.PublicKey(wallet.PublicKey[:])
	ids := party.IDSlice{1, 2, 3}
	var states [3]*state.State
	var outputs [3]*keygen.Output
	for i, id := range ids {
		view := [3]recovery.Ed25519PublicContribution{public[i], public[(i+1)%3], public[(i+2)%3]}
		nodeWallet, err := recovery.CombineEd25519PublicContributions(view)
		if err != nil || nodeWallet != wallet {
			t.Fatalf("unexpected public data for node %d: %v", id, err)
		}
		states[i], outputs[i], err = frost.NewKeygenStateWithContribution(id, ids, contributions[i].Scalar[:], nodeWallet.PublicKey[:], []byte("frost-backup-keygen"), 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	runFROST(t, states)

	message := []byte("FROST mnemonic backup round trip")
	var signatures [3]*sign.Output
	for i, config := range outputs {
		if config.Public.Threshold != 2 || !expected.Equal(config.Public.GroupKey.ToEd25519()) {
			t.Fatalf("unexpected DKG output from node %d", ids[i])
		}
		states[i], signatures[i], err = frost.NewSignState(ids, config.SecretKey, config.Public, message, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	runFROST(t, states)
	for _, out := range signatures {
		if out.Signature == nil || !ed25519.Verify(expected, message, out.Signature.ToEd25519()) {
			t.Fatal("invalid FROST signature")
		}
	}

	key, err := recovery.RecoverEd25519PrivateKey(words, wallet)
	if err != nil {
		t.Fatal(err)
	}
	if key.ChainCode != wallet.ChainCode {
		t.Fatal("unexpected recovered chain code")
	}
	if !ed25519.Verify(expected, message, signWithScalar(t, key.Scalar, expected, message)) {
		t.Fatal("offline signature failed verification against the DKG public key")
	}
}

func runFROST(t *testing.T, states [3]*state.State) {
	t.Helper()
	var incoming [][]byte
	for round := 0; round < 3; round++ {
		var outgoing [][]byte
		for _, s := range states {
			messages, err := helpers.PartyRoutine(incoming, s)
			if err != nil {
				t.Fatal(err)
			}
			outgoing = append(outgoing, messages...)
		}
		incoming = outgoing
	}
	for _, s := range states {
		if !s.IsFinished() {
			t.Fatal("FROST session did not finish")
		}
	}
}

// signWithScalar is a test-only Ed25519 signer with a fresh random nonce.
func signWithScalar(t *testing.T, scalar [32]byte, publicKey, message []byte) []byte {
	t.Helper()
	private, err := edwards25519.NewScalar().SetCanonicalBytes(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	var random [64]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	nonce, err := edwards25519.NewScalar().SetUniformBytes(random[:])
	if err != nil {
		t.Fatal(err)
	}
	commitment := new(edwards25519.Point).ScalarBaseMult(nonce).Bytes()
	h := sha512.New()
	h.Write(commitment)
	h.Write(publicKey)
	h.Write(message)
	challenge, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	response := edwards25519.NewScalar().MultiplyAdd(challenge, private, nonce)
	return append(commitment, response.Bytes()...)
}
