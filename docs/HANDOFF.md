# HANDOFF — Agent 交接文档

生成：2026-09-26 · 状态：workspace 182 passed / 0 failed

## 项目概况

CTF2 平台 (ctf2.dasctf.com) 自动化解题项目。零依赖 Python 客户端 + 纯 Rust
解题工具链（ctf-forge CLI / MCP）+ Agent Skill（.agents/skills/ctf2-platform/）。

## 核心能力（tools → CLI 命令）

| 能力 | 模块 | CLI 命令 |
|---|---|---|
| RSA 攻击树 | ctf-crypto::rsa | `crypto_rsa --attack auto` |
| **Coppersmith 小根** | ctf-crypto::lattice | **`lattice --op small_roots`** ✨NEW |
| LCG/MT19937 | ctf-crypto::{lcg,mt19937} | `prng --kind lcg` |
| LCG 六输出盲恢复 | ctf-crypto::lcg | `recover_seed_six()` ✨NEW |
| Keccak-256 + secp256k1 + ETH 地址 | ctf-crypto::ecc | `eth_address()` ✨NEW |
| MD4 + NetNTLMv2 | ctf-crypto::ntlm | `ntlmv2_hashcat_line()` ✨NEW |
| 编码链 | ctf-codec::auto/xcode | `codec --op auto` |
| USB HID 键盘 | ctf-codec::hid | `decode_keyboard_reports()` ✨NEW |
| pcap/pcapng + USB HID | ctf-parse::pcap | `forensics --op pcap` ✨NEW |
| **内存雕刻** | ctf-parse::rawmem | **`forensics --op memscan`** ✨NEW |
| **Minidump 解析** | ctf-parse::minidump | **`forensics --op minidump`** ✨NEW |
| **内核转储 PAGEDU64+KDBG** | ctf-parse::pagedump | **`forensics --op pagedump`** ✨NEW |
| **NTFS $MFT 记录** | ctf-parse::mft | **`forensics --op mft`** ✨NEW |
| **SQLite b-tree 读取** | ctf-parse::sqlite | **`forensics --op sqlite`** ✨NEW |
| **注册表 hive 解析** | ctf-parse::regf | `find_hives()` ✨NEW |
| **磁盘 MBR/GPT/FAT32** | ctf-parse::disk | 分区表 + FAT32 LFN ✨NEW |
| HTTP/DNS 协议解析 | ctf-parse::netproto | netproto::parse_http/parse_dns ✨NEW |
| fmtstr 写构造 | ctf-pwn::fmtstr | `IncrementalFmt` ✨NEW |
| 栈机解释器 | ctf-pwn::stackvm | `run()` ✨NEW |
| ELF/ROP/堆 | ctf-pwn | 既有 |
| 大数分解 | tools/yafu sidecar | `sidecar_run --engine yafu` |
| CTF2 平台 I/O | ctf-forge-cli::ctf2client | `ctf2 practice/get/daily` |

✨NEW = 本轮（2026-09-26）新增，182 测试全绿。

## 构建与测试

```bash
cargo test --workspace          # 182 passed / 0 failed
cargo build --release -p ctf-forge-cli
./target/release/ctf-forge.exe --help
```

## CTF2 真实赛题验证成果（2026-09-26）

| 验证域 | 语料 | 结果 |
|---|---|---|
| 流量解析 | 101 个 CTF2 归档 pcap/pcapng | 99% 解析成功 |
| DNS exfil | stealer 挑战 3904 条 DNS | 1944 子域→base64→**81KB PNG 提取** ✓ |
| 磁盘 memscan | XMAN 2018 10MB ext4 | UTF-16LE 雕刻→**flag{fugly_cats_need_luv_2}** ✓ |
| HID 键盘 | 手把天尊 111k 包 | 6072 字符流提取 ✓ |
| pcap 魔数 | tele.pcap | 0xa1b2cd34 CTF 变体支持 ✓ |
| ETH 地址 | 华为杯 2024 真实向量 | 0x34c5a8cb…E186 ✓ |
| Coppersmith | 合成 beta=1/2 + beta=1 | 两测试全过 ✓ |

批量扫描结果：`.tmp/work/pcap_sweep_results.json`
DNS exfil 提取 PNG：`.tmp/work/cli_smoke/stealer_extract.png`（81KB）
磁盘 flag：`.tmp/work/cli_smoke/mem.raw` / `challenges/ctf2/buuctf/MISC/_XMAN2018排位赛_file/`

## 华为杯赛题库（59 题分析报告）

`.tmp/赛题分析报告.md` — 2022–2025 全量分析（实网 52 + 研发 7），含：
- 2024 决赛 5 Pwn 深度分析（无题解缺口填补， Vegetables/story/ez_exchange/baby_linklist/springboard）
- CTF2 真实赛题验证（DNS exfil/磁盘 memscan/HID/pcap 魔数）
- 2022–2025 考点演进趋势 + 备赛建议

## 待办（按优先级，接手者从这里开始）

### P1 — 能力补全
1. **apbq 正交格 Rust 移植** — Python oracle 已验证（work/y2024q/coppersmith.py），
   naive 6 维核嵌入返回 gcd=1 混合核向量，需论文级核验（可能需要 adjugate 构造而非直接嵌入）
2. **ext2/ext4 读取器** — XMAN 2018 img 是 ext4（magic @0x438），当前只能 memscan
   无法遍历目录树；MFT+sqlite+regf 模式可复用（inode→属性→数据块）
3. **USB 数位板 HID 坐标还原** — Draw_what_you_like 考点，HID Usage Table Digitizer
   页面（report 格式设备特定，需参数化 x/y offset + scale）
4. **pcapng 完整块支持** — 当前只解析 EPB；补 NRB/ISB/自定义块、IDB linktype 暴露
5. **TLS 解析** — DASBOOK 第09章_TLS流量分析（ClientHello SNI 提取等）

### P2 — CTF2 平台刷题
6. **BUUCTF-Real MISC 系列** — 278 题，流量/取证类直接用新 forensics 工具
7. **DASBOOK 第07-13章** — 图像隐写/音频/磁盘取证/反编译（queue: dasbook 0/92 parsed）
8. **N1BOOK 46 题** — 含 blockchain/web 入门
9. **CTF2 daily 20 题** — 12 BLOCKED_ENV（需启动环境）、6 BLOCKED_NO_DATA

### P3 — 已知限制
10. Coppersmith dim>24 慢（纯 Rust 精确有理 LLL），fplll FFI 是候选优化
11. apbq 正交格见 P1#1
12. pcap 2 个失败文件（tele.pcap）已加魔数支持但解析结果仅 1 包（非以太网链路）

## 文件索引

| 文件 | 内容 |
|---|---|
| docs/COMPETENCY.md | 能力域×工具×CTF2 刷题路径矩阵 |
| docs/CAPABILITIES.md | 37 域能力覆盖状态 |
| docs/KNOWLEDGE.md | 技术卡（preconditions/I/O/failure mode/vector） |
| docs/CHALLENGE-LOG.md | 逐题记录（含 CTF2 验证 + 华为杯分析） |
| docs/DEPS.md | 依赖台账 + 算法出处 |
| docs/PROGRESS.md | 全量进展日志 |
| docs/QUEUE.json | CTF2 daily/grounds 状态 |
| .tmp/赛题分析报告.md | 华为杯 59 题全量分析报告 |
| .tmp/work/y2024f/ | 2024 决赛分析产物 |
| .tmp/work/y2024q/ | 2024 初赛复现脚本（coppersmith.py 等） |
| .tmp/work/y2025r/ | 2025+研发赛道产物 |
| .tmp/work/pcap_sweep_results.json | CTF2 101 pcap 批量扫描结果 |
| .tmp/work/cli_smoke/ | CLI 冒烟测试 fixtures + 产物 |
| challenges/ctf2/ | CTF2 平台归档题目（含 101 pcap 文件列表） |
| challenges/ | 挑战归档根目录 |
| .agents/skills/ctf2-platform/ | CTF2 平台 Agent Skill（Open API 参考） |
