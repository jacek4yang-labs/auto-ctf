# ctf-forge — 纯 Rust CTF 解题工具链

一个 Rust-first 的 CTF 自动化工具链：从 RSA / 格密码 / PRNG 到取证（pcap、内存雕刻、磁盘、注册表、SQLite）、pwn（fmtstr、栈机、ROP）和平台 I/O，全部用纯 Rust 实现，零 Python / SageMath 运行时依赖。

> 项目代号 `auto-ctf`。早期有一个零依赖 Python CTF2 客户端，已退役为参考实现（见 `refs/oracle/`），生产路径全面迁移到 Rust workspace。

## 为什么是 Rust

策略优先级（见 [`docs/DEPS.md`](docs/DEPS.md)）：

> 纯 safe Rust → Rust FFI → Rust sidecar 包裹原生工具 → 外部可执行文件。
> Python / SageMath 仅作算法参考（保存在 `refs/oracle/`），永不作为运行时依赖。

每个第三方引用都记录：原始项目、来源 URL、许可证、所用算法、对应 Rust 实现位置。

## Workspace 结构

```
crates/
├── ctf-core        # 大数、hash(SHA-256/MD5)、num 工具
├── ctf-codec       # 编码链 auto/xcode、USB HID 键盘
├── ctf-crypto      # RSA 攻击树、Coppersmith 小根、LCG/MT19937、ECC/ETH 地址、NTLM
├── ctf-parse       # pcap/pcapng、内存雕刻、Minidump、PAGEDU64、$MFT、SQLite、regf、磁盘 MBR/GPT/FAT32、HTTP/DNS
├── ctf-pwn         # ELF/ROP/堆、fmtstr 写构造、栈机解释器
├── ctf-tube        # 二进制安全 IO（复用上游 jacek4yang/rnc）+ gbk/gb18030
├── ctf-net         # 网络原语
├── ctf-sidecar     # 外部可执行文件 sidecar（sha256 固定 + 超时 + 解析 + 测试）
├── ctf-forge-cli   # CLI 入口：crypto_rsa / prng / codec / forensics / ctf2 …
└── ctf-forge-mcp   # stdio MCP 服务（~120 行 serde_json，无 rmcp 运行时依赖）
vendor/rnc          # 上游 jacek4yang/rnc（MIT），ctf-tube 的 path 依赖
```

`ctf-tube` 通过 path 依赖引用 `vendor/rnc`，因此 `vendor/rnc` 随仓库分发；`vendor/reverse-mcp`（IDA MCP broker）是独立项目，不在此 workspace，按需在上游获取。

## 快速开始

需要 Rust 工具链（rustc ≥ 1.88，因为 `rmcp` 已解禁；运行时实际不依赖 rmcp）。

```bash
# 克隆（vendor/rnc 是 submodule，构建 ctf-tube 需要）
git clone --recurse-submodules https://github.com/jacek4yang-labs/auto-ctf.git
cd auto-ctf
# 若已裸克隆，补拉 submodule：git submodule update --init

# 全量测试
cargo test --workspace          # 182 passed / 0 failed

# 构建发布版 CLI
cargo build --release -p ctf-forge-cli
./target/release/ctf-forge --help
```

### 能力速览（tools → CLI 命令）

| 能力 | 模块 | CLI 命令 |
|---|---|---|
| RSA 攻击树（auto/wiener/fermat/from_pq/dp_leak/...） | ctf-crypto::rsa | `crypto_rsa --attack auto` |
| Coppersmith 小根 | ctf-crypto::lattice | `lattice --op small_roots` |
| LCG / MT19937（含六输出盲恢复） | ctf-crypto::{lcg,mt19937} | `prng --kind lcg` |
| Keccak-256 + secp256k1 + ETH 地址 | ctf-crypto::ecc | `eth_address()` |
| MD4 + NetNTLMv2 | ctf-crypto::ntlm | `ntlmv2_hashcat_line()` |
| 编码链 / USB HID 键盘 | ctf-codec | `codec --op auto` |
| pcap/pcapng + USB HID | ctf-parse::pcap | `forensics --op pcap` |
| 内存雕刻 / Minidump / PAGEDU64+KDBG | ctf-parse | `forensics --op {memscan,minidump,pagedump}` |
| $MFT / SQLite / 注册表 hive / 磁盘 MBR/GPT/FAT32 | ctf-parse | `forensics --op {mft,sqlite,regf,...}` |
| fmtstr 写构造 / 栈机解释器 / ELF/ROP/堆 | ctf-pwn | — |
| CTF2 平台只读 I/O | ctf-forge-cli::ctf2client | `ctf2 practice/get/daily` |

完整能力矩阵见 [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)，技术卡（前置条件 / I/O / 失败模式 / 合成测试向量）见 [`docs/KNOWLEDGE.md`](docs/KNOWLEDGE.md)。

## 真实赛题验证（节选）

| 验证域 | 语料 | 结果 |
|---|---|---|
| 流量解析 | 101 个 CTF2 归档 pcap/pcapng | 99% 解析成功 |
| DNS exfil | stealer 挑战 3904 条 DNS | 1944 子域 → base64 → 81KB PNG 提取 ✓ |
| 磁盘 memscan | XMAN 2018 10MB ext4 | UTF-16LE 雕刻 → flag ✓ |
| HID 键盘 | 手把天尊 111k 包 | 6072 字符流提取 ✓ |
| ETH 地址 | 华为杯 2024 真实向量 | 0x34c5a8cb…E186 ✓ |

逐题记录见 [`docs/CHALLENGE-LOG.md`](docs/CHALLENGE-LOG.md)。

## 安全约定

- CTF2 PAT **只**从环境变量 `CTF2_TOKEN` 读取，绝不写进代码、日志或配置文件。
- 库层面强制：提交 flag、更新资料等写操作必须显式 `confirm=True`；默认只做只读。
- 遵守平台限流与 `Retry-After`，不做批量猜 flag。
- 仓库自带 `scripts/scan_flag_leaks.py`，扫描 `challenges/`、`docs/`、`skills/`、`scripts/` 中未脱敏的 flag，确保发布前零泄漏。

## 仓库中**不**包含的内容

为控制体积与版权风险，本仓库只发布自研工具链与文档：

- `challenges/`（从各平台拉取的题目附件，11k+ 文件）— 不纳入；解题知识已蒸馏到 `docs/CHALLENGE-LOG.md`。
- `tools/`（bkcrack / hashcat / yafu 等第三方可执行文件）— 不纳入；yafu 通过 `ctf-sidecar` 按需调用本地安装。
- `vendor/reverse-mcp`（IDA MCP broker，独立上游）— 不纳入。
- `target/`、`.tmp/`、`*.log` / `*.dat` 等构建与运行产物 — 已被 `.gitignore` 排除。

## 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/HANDOFF.md`](docs/HANDOFF.md) | 交接总览：能力表 + 验证成果 + 待办 |
| [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) | 37 域能力覆盖状态 |
| [`docs/COMPETENCY.md`](docs/COMPETENCY.md) | 能力域 × 工具 × 刷题路径矩阵 |
| [`docs/KNOWLEDGE.md`](docs/KNOWLEDGE.md) | 技术卡（前置 / I/O / 失败模式 / 向量） |
| [`docs/CHALLENGE-LOG.md`](docs/CHALLENGE-LOG.md) | 逐题记录（含真实赛题验证） |
| [`docs/DEPS.md`](docs/DEPS.md) | 依赖台账 + 算法出处 |
| [`docs/PROGRESS.md`](docs/PROGRESS.md) | 全量进展日志 |
| [`docs/UPSTREAM.md`](docs/UPSTREAM.md) | 上游来源说明 |

## 许可证

MIT（见各 crate `Cargo.toml` 的 `license` 字段）。`vendor/rnc` 同为 MIT（上游 `jacek4yang/rnc`）。`.agents/skills/ctf2-platform` 为平台官方 MIT Agent Skill。
