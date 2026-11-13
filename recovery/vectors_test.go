package recovery_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-wallet-recovery/recovery"
	"github.com/tyler-smith/go-bip39"
)

func TestSafeheronCMPVectors(t *testing.T) {
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
		Source  string
		Parties [3]vector
		Wallet  vector
	}
	readFixture(t, "bip39-mnemonics.json", &input)
	readFixture(t, "safeheron-cmp-v2.json", &expected)
	if expected.Source != "@safeheron/master-key-derive@2.0.1" {
		t.Fatal("unexpected fixture source")
	}

	var mnemonics [3]string
	var public [3]recovery.CMPPublicContribution
	for i, node := range input.Parties {
		want := expected.Parties[i]
		if node.ID == "" || node.ID != want.ID {
			t.Fatalf("fixture party %d does not match", i+1)
		}
		mnemonics[i] = node.Mnemonic
		contribution, err := recovery.DeriveCMPContribution(node.Mnemonic)
		if err != nil {
			t.Fatal(err)
		}
		public[i] = contribution.Public
		checkHex(t, contribution.Scalar[:], want.Scalar)
		checkHex(t, public[i].PublicKey[:], want.PublicKey)
		checkHex(t, public[i].ChainCode[:], want.ChainCode)
		if err := recovery.VerifyCMPBackup(node.Mnemonic, public[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := recovery.VerifyCMPBackup(mnemonics[0], public[1]); err == nil {
		t.Fatal("accepted a backup from another node")
	}
	wrongPublic := public[0]
	wrongPublic.ChainCode[0] ^= 1
	if err := recovery.VerifyCMPBackup(mnemonics[0], wrongPublic); err == nil {
		t.Fatal("accepted wrong node chain code")
	}
	wallet, err := recovery.CombineCMPPublicContributions(public)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, wallet.PublicKey[:], expected.Wallet.PublicKey)
	checkHex(t, wallet.ChainCode[:], expected.Wallet.ChainCode)
	mnemonics[0], mnemonics[2] = mnemonics[2], mnemonics[0]
	key, err := recovery.RecoverCMPPrivateKey(mnemonics, wallet)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, key.Scalar[:], expected.Wallet.Scalar)
	checkHex(t, key.ChainCode[:], expected.Wallet.ChainCode)

	wrongWallet := wallet
	wrongWallet.PublicKey[0] ^= 1
	if key, err := recovery.RecoverCMPPrivateKey(mnemonics, wrongWallet); err == nil || key != (recovery.CMPPrivateKey{}) {
		t.Fatal("returned key material for a mismatched public key")
	}
	wrongWallet = wallet
	wrongWallet.ChainCode[0] ^= 1
	if key, err := recovery.RecoverCMPPrivateKey(mnemonics, wrongWallet); err == nil || key != (recovery.CMPPrivateKey{}) {
		t.Fatal("returned key material for a mismatched chain code")
	}
	mnemonics[0] = mnemonics[1]
	if _, err := recovery.RecoverCMPPrivateKey(mnemonics, wallet); err == nil {
		t.Fatal("accepted duplicate backup phrase")
	}
	public[0].PublicKey[0] = 4
	if _, err := recovery.CombineCMPPublicContributions(public); err == nil {
		t.Fatal("accepted invalid public contribution")
	}
}

func TestInvalidMnemonicErrors(t *testing.T) {
	_, err := recovery.DeriveCMPContribution(strings.TrimSpace(strings.Repeat("abandon ", 24)))
	if !errors.Is(err, recovery.ErrMnemonicChecksum) {
		t.Fatalf("expected checksum error, got %v", err)
	}
	const invalidWord = "fixture-unknown-secret"
	_, err = recovery.DeriveCMPContribution(strings.Repeat("abandon ", 23) + invalidWord)
	if !errors.Is(err, recovery.ErrMnemonicWord) {
		t.Fatalf("expected unknown-word error, got %v", err)
	}
	if strings.Contains(err.Error(), invalidWord) {
		t.Fatal("error disclosed an input word")
	}
}

func TestGenerateMnemonic(t *testing.T) {
	phrase, err := recovery.GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(phrase)) != 24 {
		t.Fatal("expected a 24-word mnemonic")
	}
	if _, err := recovery.DeriveCMPContribution(phrase); err != nil {
		t.Fatalf("generated mnemonic did not derive: %v", err)
	}
	short, err := bip39.NewMnemonic(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.DeriveCMPContribution(short); err == nil {
		t.Fatal("accepted a 12-word mnemonic")
	}
}

func checkHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("fixture mismatch: got %x, want %s", got, want)
	}
}

func readFixture(t *testing.T, name string, dst any) {
	t.Helper()
	data, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatal(err)
	}
}
