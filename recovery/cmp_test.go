package recovery_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/C18519898242/mpc-wallet-recovery/recovery"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	cmpsig "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/tyler-smith/go-bip39"
)

func TestCMPBackup(t *testing.T) {
	data, err := os.ReadFile("../testdata/bip39-mnemonics.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Parties [3]struct {
			ID       party.ID `json:"party_id"`
			Mnemonic string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	var mnemonics [3]string
	var ids [3]party.ID
	var local [3][32]byte
	var public [3]recovery.CMPPublicContribution
	for i, party := range fixture.Parties {
		ids[i] = party.ID
		mnemonics[i] = party.Mnemonic
		contribution, err := recovery.DeriveCMPContribution(party.Mnemonic)
		if err != nil {
			t.Fatalf("derive party %d: %v", i, err)
		}
		public[i] = contribution.Public
		local[i] = contribution.Scalar
		if i == 0 {
			checkHex(t, contribution.Scalar[:], "97e60659bba289f86c0638d0ef2551d61ab3c3d5bfdbf78ed815bd3c9ba51dd9")
			checkHex(t, contribution.Public.ChainCode[:], "27b7fdfc0f65b95d2405e3766ac1d2e1ee60ee528dd0ca55c05e97e82fd01cd5")
		}
	}
	wallet, err := recovery.CombineCMPPublicContributions(public)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, wallet.PublicKey[:], "03e57ea0c65c0150165a573d9fd29934862052e3248a3427b28d9d1a708981f54c")
	checkHex(t, wallet.ChainCode[:], "e458ec236a31021aa5185d6996ea117e9f63ce8c12cdb9e50161df204e42428d")

	starts := [3]protocol.StartFunc{}
	for i, id := range ids {
		starts[i] = cmp.ImportKey(id, ids[:], local[i][:], wallet.PublicKey[:], wallet.ChainCode[:], nil)
	}
	configs := runCMP(t, ids, "mnemonic-wallet-keygen", starts)
	digest := sha256.Sum256([]byte("CMP mnemonic backup round trip"))
	for i, result := range configs {
		config := result.(*cmp.Config)
		point, err := config.PublicPoint().MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		checkHex(t, point, hex.EncodeToString(wallet.PublicKey[:]))
		checkHex(t, config.ChainKey, hex.EncodeToString(wallet.ChainCode[:]))
		if !config.CanSign(ids[:]) || config.CanSign(ids[:2]) {
			t.Fatal("expected 3-of-3 signing")
		}
		starts[i] = cmp.Sign(config, ids[:], digest[:], nil)
	}
	for i, result := range runCMP(t, ids, "mnemonic-wallet-sign", starts) {
		if !result.(*cmpsig.Signature).Verify(configs[i].(*cmp.Config).PublicPoint(), digest[:]) {
			t.Fatal("invalid CMP signature")
		}
	}

	mnemonics[0], mnemonics[2] = mnemonics[2], mnemonics[0]
	key, err := recovery.RecoverCMPPrivateKey(mnemonics, wallet)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, key[:], "c95d706be029a225a57824647623ff3a406ce1cc5a4c49c2bfb0e43d3542aeed")
	pub, err := secp256k1.ParsePubKey(wallet.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	recovered := secp256k1.PrivKeyFromBytes(key[:])
	defer recovered.Zero()
	if !ecdsa.Sign(recovered, digest[:]).Verify(digest[:], pub) {
		t.Fatal("recovered key failed to sign for the same public key")
	}

	wrongWallet := wallet
	wrongWallet.ChainCode[0] ^= 1
	if _, err := recovery.RecoverCMPPrivateKey(mnemonics, wrongWallet); err == nil {
		t.Fatal("accepted wrong chain code")
	}
	wrongWallet = wallet
	wrongWallet.PublicKey[0] ^= 1
	if _, err := recovery.RecoverCMPPrivateKey(mnemonics, wrongWallet); err == nil {
		t.Fatal("accepted wrong public key")
	}
	mnemonics[0] = mnemonics[1]
	if _, err := recovery.RecoverCMPPrivateKey(mnemonics, wallet); err == nil {
		t.Fatal("accepted duplicate backup phrase")
	}
	public[0] = recovery.CMPPublicContribution{}
	if _, err := recovery.CombineCMPPublicContributions(public); err == nil {
		t.Fatal("accepted invalid public contribution")
	}
}

func runCMP(t *testing.T, ids [3]party.ID, session string, starts [3]protocol.StartFunc) [3]interface{} {
	t.Helper()
	var handlers [3]*protocol.MultiHandler
	var outgoing [3]<-chan *protocol.Message
	for i, start := range starts {
		handler, err := protocol.NewMultiHandler(start, []byte(session))
		if err != nil {
			t.Fatal(err)
		}
		handlers[i] = handler
		outgoing[i] = handler.Listen()
	}
	// Route the buffered messages in-process. If a full pass delivers nothing,
	// a handler cannot advance without an input it never received.
	for {
		delivered := false
		for _, messages := range outgoing {
			select {
			case msg, open := <-messages:
				if !open {
					continue
				}
				for i, id := range ids {
					if msg.IsFor(id) {
						handlers[i].Accept(msg)
					}
				}
				delivered = true
			default:
			}
		}
		if !delivered {
			break
		}
	}
	var results [3]interface{}
	for i, handler := range handlers {
		result, err := handler.Result()
		if err != nil {
			t.Fatalf("CMP session %s, party %s: %v", session, ids[i], err)
		}
		results[i] = result
	}
	return results
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
	for _, invalid := range []string{short, strings.TrimSpace(strings.Repeat("abandon ", 24))} {
		if _, err := recovery.DeriveCMPContribution(invalid); err == nil {
			t.Fatal("accepted invalid mnemonic")
		}
	}
}

func checkHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("fixture mismatch: got %x, want %s", got, want)
	}
}
