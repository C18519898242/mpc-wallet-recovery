const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const {
  MasterKeyPair, Mnemonics, Purpose, SigAlg, mnemonicToExtendedPub,
} = require('@safeheron/master-key-derive');
const { Secp256k1HDKey } = require('@safeheron/crypto-bip32');
const { version } = require('@safeheron/master-key-derive/package.json');

if (version !== '2.0.1') throw new Error('Expected @safeheron/master-key-derive@2.0.1');

const { test_only, parties } = JSON.parse(readFileSync(join(__dirname, 'bip39-mnemonics.json'), 'utf8'));
if (test_only !== true) throw new Error('Expected public test mnemonics');
const algorithm = SigAlg.ECDSA_SECP256K1;
const purpose = Purpose.MASTER_KEY_DERIVE;
const alternativeIndex = 0;
const paddedHex = value => value.toString(16).padStart(64, '0');
const compressedHex = xpub => Secp256k1HDKey.fromExtendedKey(xpub).publicKey.encodeCompressed('hex');

const wallet = MasterKeyPair.recoverFromMnemonics(
  parties.map(({ mnemonic }) => new Mnemonics(mnemonic, '')),
  algorithm,
);
const master = Secp256k1HDKey.fromExtendedKey(wallet.xprv);
const vectors = {
  source: '@safeheron/master-key-derive@' + version,
  algorithm: 'ECDSA_SECP256K1',
  purpose: 'MASTER_KEY_DERIVE',
  alternative_index: alternativeIndex,
  parties: parties.map(({ party_id, mnemonic }) => {
    const share = new Mnemonics(mnemonic, '').derive(purpose, algorithm, alternativeIndex);
    return {
      party_id,
      scalar: paddedHex(share.keyShare),
      chain_code: paddedHex(share.chainCodeShare),
      public_key: compressedHex(mnemonicToExtendedPub(algorithm, alternativeIndex, mnemonic)),
    };
  }),
  wallet: {
    scalar: paddedHex(master.privateKey),
    chain_code: paddedHex(master.chainCode),
    public_key: compressedHex(wallet.xpub),
  },
};
process.stdout.write(JSON.stringify(vectors, null, 2) + '\n');
