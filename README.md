# MPC Wallet Recovery

用于备份和离线恢复 3-of-3 MPC 钱包的 Go 模块。目前支持 CMP / ECDSA（secp256k1）主密钥。

| 目录 | 用途 |
| --- | --- |
| `recovery` | 助记词派生与密钥恢复 |
| `testdata` | 固定测试向量 |
| `integration` | 使用 CMP fork 的三方建钥和签名测试 |

当前提供 Go API。离线 CLI 尚未实现。

## 创建并备份 CMP 钱包

1. 每个节点在本地调用 `recovery.GenerateMnemonic()`，分别生成并备份自己的 24 个英文 BIP-39 词。妥善保存原始助记词，签名分片无法反推出原词。
2. 每个节点调用 `recovery.DeriveCMPContribution(mnemonic)`。助记词和返回的 `Scalar` 只留在本节点。应用通过已认证的通道交换 `Public` 字段，并把每份数据绑定到本次建钱包会话及其节点 ID。各节点确认收到的是同一套公开数据。
3. 各节点用实际备份的词和本节点发布的公开数据调用 `recovery.VerifyCMPBackup`。核对通过后，用三份公开数据调用 `recovery.CombineCMPPublicContributions`，得到共用的 `wallet.PublicKey` 和 `wallet.ChainCode`。钱包记录应独立保存这两个值，以及按节点 ID 记录的三份公开贡献，供离线核对。
4. 各节点用自己的 `contribution.Scalar` 启动 CMP，使用同一个唯一的会话 ID，通过原有的加密、认证传输层运行协议。完成后保存各自的 `*cmp.Config`，用于日常签名。

```go
start := cmp.ImportKey(
    selfID, participants, contribution.Scalar[:],
    wallet.PublicKey[:], wallet.ChainCode[:], pool,
)
handler, err := protocol.NewMultiHandler(start, sessionID)
```

CMP 需要包含 `ImportKey` 的分支版本。`integration/go.mod` 将上游模块路径映射到含该接口的 fork，钱包应用可参考该文件配置 CMP 依赖。恢复主模块无需 CMP fork。
集成测试锁定 fork 提交 `163e25a3`。相对其上游基线 `d489e309`，fork 增加了私钥贡献导入及其会话绑定和聚合公钥校验。影响建钥耗时的 `ZKModIterations = 128` 已存在于该基线。
导入协议核对聚合后的公钥，各节点负责确保自己发布的公开数据和本地提交的贡献来自同一组词。

## 离线恢复

在离线环境中，可用 `recovery.VerifyCMPBackup` 逐组核对助记词和对应节点的记录，以定位抄错的备份。再将三组词和建钱包时独立保存的 `wallet` 交给
`recovery.RecoverCMPPrivateKey([3]string{alice, bob, carol}, wallet)`。
三组词的顺序任意。核对通过后，函数返回 `CMPPrivateKey`，包含可独立签名的 32 字节
secp256k1 主私钥 `Scalar` 及其 `ChainCode`。创建和日常签名阶段无需重建完整私钥。

助记词按 Safeheron V2 的 secp256k1 主贡献规则派生，每个节点一组 24 个英文 BIP-39 词，派生索引固定为零。建钱包时若遇到零标量或聚合公钥为无穷远点，使用新助记词重新建钱包。旧版 V1 的完整 chain code 格式请用 Safeheron 官方工具恢复。
已用普通 DKG 创建的钱包仍需使用原有分片备份。
`testdata` 中的助记词是公开测试数据，仅用于测试。

## 测试

- 根目录运行 `go test ./...`，核对官方向量和恢复校验。
- 在 `integration` 目录运行 `go test ./... -timeout=120s`，验证三方建钥、RID 一致性，以及 MPC 签名和离线私钥签名都能通过原公钥验签。

官方向量由 `@safeheron/master-key-derive@2.0.1` 从公开测试词生成。可在临时目录用 `npm install --ignore-scripts --save-exact @safeheron/master-key-derive@2.0.1` 安装该包，将 `NODE_PATH` 指向临时目录的 `node_modules`，再从项目根目录运行 `node testdata/generate-safeheron-cmp.cjs`，将输出与 `testdata/safeheron-cmp-v2.json` 对照。
