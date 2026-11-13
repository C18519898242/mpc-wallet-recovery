package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/C18519898242/mpc-wallet-recovery/recovery"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	cmpsig "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
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
	for i, node := range fixture.Parties {
		ids[i] = node.ID
		mnemonics[i] = node.Mnemonic
		contribution, err := recovery.DeriveCMPContribution(node.Mnemonic)
		if err != nil {
			t.Fatalf("derive party %d: %v", i, err)
		}
		public[i] = contribution.Public
		local[i] = contribution.Scalar
		if err := recovery.VerifyCMPBackup(node.Mnemonic, public[i]); err != nil {
			t.Fatalf("verify backup for %s: %v", node.ID, err)
		}
	}
	wallet, err := recovery.CombineCMPPublicContributions(public)
	if err != nil {
		t.Fatal(err)
	}

	starts := [3]protocol.StartFunc{}
	for i, id := range ids {
		view := [3]recovery.CMPPublicContribution{public[i], public[(i+1)%3], public[(i+2)%3]}
		nodeWallet, err := recovery.CombineCMPPublicContributions(view)
		if err != nil || nodeWallet != wallet {
			t.Fatalf("different wallet for node %s: %v", id, err)
		}
		starts[i] = cmp.ImportKey(id, ids[:], local[i][:], nodeWallet.PublicKey[:], nodeWallet.ChainCode[:], nil)
	}
	configs := runCMP(t, ids, "mnemonic-wallet-keygen", starts)
	digest := sha256.Sum256([]byte("CMP mnemonic backup round trip"))
	for i, result := range configs {
		config := result.(*cmp.Config)
		point, err := config.PublicPoint().MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(point, wallet.PublicKey[:]) || !bytes.Equal(config.ChainKey, wallet.ChainCode[:]) {
			t.Fatalf("unexpected wallet for node %s (public key %s)", ids[i], hex.EncodeToString(point))
		}
		if len(config.RID) != 32 || !bytes.Equal(config.RID, configs[0].(*cmp.Config).RID) {
			t.Fatalf("unexpected CMP RID for node %s", ids[i])
		}
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
	if key.ChainCode != wallet.ChainCode {
		t.Fatal("recovered key has an unexpected chain code")
	}
	pub, err := secp256k1.ParsePubKey(wallet.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	recovered := secp256k1.PrivKeyFromBytes(key.Scalar[:])
	defer recovered.Zero()
	if !ecdsa.Sign(recovered, digest[:]).Verify(digest[:], pub) {
		t.Fatal("recovered key failed to sign for the same public key")
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
