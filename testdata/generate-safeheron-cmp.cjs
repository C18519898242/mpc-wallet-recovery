const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const {
  MasterKeyPair, Mnemonics, Purpose, SigAlg, mnemonicToExtendedPub,
  ed25519_get_pubkey_hex,
} = require('@safeheron/master-key-derive');
const { Secp256k1HDKey, Ed25519HDKey } = require('@safeheron/crypto-bip32');
const { version } = require('@safeheron/master-key-derive/package.json');

if (version !== '2.0.1') throw new Error('Expected @safeheron/master-key-derive@2.0.1');

const { test_only, parties } = JSON.parse(readFileSync(join(__dirname, 'bip39-mnemonics.json'), 'utf8'));
if (test_only !== true) throw new Error('Expected public test mnemonics');
const ed25519 = process.argv[2] === 'ed25519';
const algorithm = ed25519 ? SigAlg.EDDSA_ED25519 : SigAlg.ECDSA_SECP256K1;
const purpose = Purpose.MASTER_KEY_DERIVE;
const alternativeIndex = 0;
const paddedHex = value => value.toString(16).padStart(64, '0');
const compressedHex = xpub => Secp256k1HDKey.fromExtendedKey(xpub).publicKey.encodeCompressed('hex');
const scalarHex = value => ed25519
  ? Buffer.from(paddedHex(value), 'hex').reverse().toString('hex')
  : paddedHex(value);

const wallet = MasterKeyPair.recoverFromMnemonics(
  parties.map(({ mnemonic }) => new Mnemonics(mnemonic, '')),
  algorithm,
);
const master = (ed25519 ? Ed25519HDKey : Secp256k1HDKey).fromExtendedKey(wallet.xprv);
const vectors = {
  source: '@safeheron/master-key-derive@' + version,
  algorithm: SigAlg[algorithm],
  purpose: 'MASTER_KEY_DERIVE',
  alternative_index: alternativeIndex,
  parties: parties.map(({ party_id, mnemonic }) => {
    const share = new Mnemonics(mnemonic, '').derive(purpose, algorithm, alternativeIndex);
    return {
      party_id,
      scalar: scalarHex(share.keyShare),
      chain_code: paddedHex(share.chainCodeShare),
      public_key: ed25519 ? ed25519_get_pubkey_hex(share.keyShare)
        : compressedHex(mnemonicToExtendedPub(algorithm, alternativeIndex, mnemonic)),
    };
  }),
  wallet: {
    scalar: scalarHex(master.privateKey),
    chain_code: paddedHex(master.chainCode),
    public_key: ed25519 ? master.publicKeyAsHex : compressedHex(wallet.xpub),
  },
};
process.stdout.write(JSON.stringify(vectors, null, 2) + '\n');
