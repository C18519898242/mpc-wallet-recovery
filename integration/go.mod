module github.com/C18519898242/mpc-wallet-recovery/integration

go 1.24.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/taurusgroup/multi-party-sig v0.0.0-20261110150323-163e25a3a0a8
)

require github.com/tyler-smith/go-bip39 v1.1.0 // indirect

require (
	github.com/C18519898242/mpc-wallet-recovery v0.0.0
	github.com/cronokirby/saferith v0.33.0 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	golang.org/x/crypto v0.10.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
)

replace github.com/taurusgroup/multi-party-sig => github.com/C18519898242/multi-party-sig v0.0.0-20261110150323-163e25a3a0a8

replace github.com/C18519898242/mpc-wallet-recovery => ..
