module github.com/C18519898242/mpc-wallet-recovery/integration/frost

go 1.24.0

require (
	filippo.io/edwards25519 v1.0.0-rc.1
	github.com/C18519898242/mpc-wallet-recovery v0.0.0
	github.com/taurusgroup/frost-ed25519 v0.0.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	golang.org/x/crypto v0.10.0 // indirect
)

replace github.com/C18519898242/mpc-wallet-recovery => ../..

replace github.com/taurusgroup/frost-ed25519 => ../../../frost-ed25519
