# MPC Wallet Recovery

用于备份和离线恢复 3-of-3 MPC 钱包的 Go 模块。目前支持 CMP / ECDSA（secp256k1）主密钥。

| 目录 | 用途 |
| --- | --- |
| `cmd/offline-recovery` | 离线恢复命令行工具 |
| `recovery` | 助记词派生与密钥恢复 |
| `testdata` | 固定测试向量 |

## 创建并备份 CMP 钱包

1. 每个节点在本地调用 `recovery.GenerateMnemonic()`，分别生成并备份自己的 24 个英文 BIP-39 词。妥善保存原始助记词，签名分片无法反推出原词。
2. 每个节点调用 `recovery.DeriveCMPContribution(mnemonic)`。助记词和返回的 `Scalar` 只留在本节点。应用通过已认证的通道交换 `Public` 字段，并把每份数据绑定到本次建钱包会话及其节点 ID。各节点确认收到的是同一套公开数据。
3. 各节点用三份公开数据调用 `recovery.CombineCMPPublicContributions`。得到的 `wallet.PublicKey` 和 `wallet.ChainCode` 是所有节点共用的输入。保存它们，供离线恢复时核对。
4. 各节点用自己的 `contribution.Scalar` 启动 CMP，使用同一个唯一的会话 ID，通过原有的加密、认证传输层运行协议。完成后保存各自的 `*cmp.Config`，用于日常签名。

```go
start := cmp.ImportKey(
    selfID, participants, contribution.Scalar[:],
    wallet.PublicKey[:], wallet.ChainCode[:], pool,
)
handler, err := protocol.NewMultiHandler(start, sessionID)
```

CMP 需要包含 `ImportKey` 的分支版本。本项目在 `go.mod` 中将上游模块路径映射到含该接口的 fork。调用方如果也导入 CMP，需要在自己的主模块中设置同样的 `replace`。
导入协议核对聚合后的公钥，各节点负责确保自己发布的公开数据和本地提交的贡献来自同一组词。

## 离线恢复

在离线环境中，将三组词和建钱包时独立保存的 `wallet` 交给
`recovery.RecoverCMPPrivateKey([3]string{alice, bob, carol}, wallet)`。
三组词的顺序任意。公钥和 chain code 都核对通过后，函数返回可独立签名的 32 字节
secp256k1 主私钥。创建和日常签名阶段无需重建这个值。

助记词按 Safeheron V2 的 secp256k1 主贡献规则派生，使用 BIP-39 解出的熵作为输入。派生索引固定为零。建钱包时若遇到零标量或聚合公钥为无穷远点，使用新助记词重新建钱包。
已用普通 DKG 创建的钱包仍需使用原有分片备份。
`testdata` 中的助记词是公开测试数据，仅用于测试。

运行 `go test ./...` 可验证三方建钥、MPC 签名和离线恢复对同一个公钥的签名。
