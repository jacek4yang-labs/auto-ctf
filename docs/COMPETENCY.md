# COMPETENCY — 华为杯能力域 × 工具链 × CTF2 刷题路径

来源：2026-09 对华为杯研究生网络安全创新大赛 2022–2025 全部 59 题的系统分析
（报告：`.tmp/赛题分析报告.md`；每个能力域的佐证题均标注年份/阶段）。
用途：刷题与工具建设都按"能力域"推进——先看差距列，再走 CTF2 路径练，
练完把新 primitive 沉淀进 crate（Rust-first policy，见 SKILL.md）。

CTF2 practice grounds（2026-09 实测）：BUUCTF 5857 · BUUCTF-Real 278 ·
DASBOOK 92 · N1BOOK 46 · BUUCTF-Basic 36。

## 能力域总览

| # | 能力域 | 华为杯佐证（题） | 工具链现状 | CTF2 刷题路径 |
|---|---|---|---|---|
| A1 | RSA 变体攻击树（dp/dq/Wiener/共模/广播/低指数） | 2022 breakMe、2023 Step_By_step、2024 EZ_RSA_5 | ✅ `crypto_rsa --attack auto` 全覆盖（ctf-crypto/rsa） | DASBOOK 第06章（14/15 已扫）→ BUUCTF-Real crypto |
| A2 | 格攻击（Coppersmith 已知高位/低位、正交格 apbq） | 2023 next-prime、2024 insecure_padding、2024 real_rsa_2 | ✅ **Rust 原生 `lattice --op small_roots`**（LLL 精确有理 + Sturm 根隔离，2026-09 落地）；apbq 正交格：Python+flint oracle 已验证，Rust 移植因核向量混合问题待论文级核验（naive 6 维嵌入返回 gcd=1 的混合核向量） | BUUCTF-Real crypto（Coppersmith 系列）→ 自己出合成实例回归（scan_tests 模式） |
| A3 | LCG/MT19937 预测与逆推 | 2022 四层挑战（四层 LCG）、2024 misc 随机数 | ✅ `prng --kind lcg`；✅ `recover_seed_six`（六输出+小倍数剥离） | DASBOOK 第06章伪随机数 → BUUCTF-Real LCG 系 |
| A4 | 经典编码/密码链 | 2022 奇怪的E、2024 广为人知的秘密 | ✅ `codec --op auto` 多层剥离 | DASBOOK 第05章（已扫）→ BUUCTF-Basic misc |
| A5 | 隐写与文件修复 | 2022 qrcode_stego、2024 Secret_Varied_Gif | 部分（codec::png/stego/zip 已有；二维码定位符修复、猪圈密码无） | N1BOOK misc → BUUCTF-Real misc |
| A6 | USB/流量取证 | 2023 神秘端口、2024 Draw_what_you_like、2025 EZ_ATEXEC | ✅ **CTF2 真实赛题验证**: 101 pcap 批量 99% 解析 + DNS exfil 提取（stealer 3904 条→PNG 81KB）+ HID 键盘（手把天尊 6072 字符）+ pcap 魔数变体 0xa1b2cd34 | BUUCTF-Real misc（流量分析系列） |
| A7 | 内存/磁盘取证 | 2024 Draw_what_you_like、2022 XMAN2018 | ✅ **CTF2 真实赛题验证**: XMAN 2018 10MB ext4 → memscan UTF-16LE → flag{fugly_cats_need_luv_2} ✓；rawmem+minidump+pagedump+regf+mft+sqlite+disk 全套 | BUUCTF-Real misc（取证系列） |
| A8 | 区块链溯源 | 2024 SeekThroughAllNetworks、广为人知的秘密 | ✅ `ctf-crypto::ecc`（keccak256+secp256k1+地址推导，Rust 原生，华为杯真题验证）；Python+web3 参考流程；学习路线 → docs/training/blockchain-security-roadmap.md | N1BOOK blockchain → CTF2 daily BLOCKCHAIN |
| A9 | Node/PHP/Java Web 漏洞面 | 2022 HackThisBox、2023 easyspark、2024 very_easyphp | ❌ Web 无原语（按政策仅授权目标） | BUUCTF-Real web → CTF2 daily WEB |
| A10 | Java RPC/中间件反序列化 | 2025 XXL-RPC、Motan、gRPC-Web | ❌（marshalsec/JNDI 环境未建） | CTF2 daily WEB（Java 系） |
| A11 | 栈 Pwn（ROP/栈迁移/ret2libc） | 2022 stack、2023 master-of-asm | ✅ `ctf-pwn`（gadget 搜索/链构造）+ `ctf-tube` | DASBOOK pwn 章节 → BUUCTF-Real pwn 入门 |
| A12 | 堆 Pwn（UAF/tcache/fastbin/堆迁移） | 2024 cancanneed_new、stack_and_heap、决赛 story | 部分（ctf-pwn 堆 helpers 缺；利用原语见 KNOWLEDGE 堆卡） | BUUCTF-Real pwn 堆系列（glibc 2.23→2.31 逐版） |
| A13 | 格式化字符串 | 2024 决赛 springboard、mips_fmt | ✅ `ctf-pwn::fmtstr`（增量写/一次性多写 builder，2026-09 落地） | BUUCTF-Real pwn fmtstr 系列 |
| A14 | seccomp 沙箱逃逸（ORW/openat2） | 2024 决赛 Vegetables、初赛 stack_and_heap | 知识卡就绪（BPF 解码+openat2 shellcode 模板）；asm 汇编器缺 | BUUCTF-Real pwn ORW 系列 |
| A15 | 内核 Pwn（UAF/cred/网络后门） | 2024 初赛 kernel-network | ❌（qemu 环境 + 模块分析未建） | BUUCTF-Real pwn kernel 系列（ babydriver 同款优先） |
| A16 | 异构架构（MIPS 大端/WASM） | 2024 初赛 mips_fmt、ezhtml | 部分（WASM 已验证 wabt 流程；MIPS 调试环境缺） | BUUCTF-Real reverse/mips |
| A17 | VM 逆向与符号执行 | 2022 infantvm、2024 downcity | 部分（downcity VM 仿真器在 work/y2024q；通用小栈机框架待沉淀） | N1BOOK reverse → BUUCTF-Real reverse |
| A18 | Windows/AD 渗透链（NTLMv2/Kerberos/SMB2） | 2025 EZ_ATEXEC（官方 0 解） | 部分（hashcat -m 5600 已验证；Kerberos/SMB 解密流程纸面） | CTF2 daily FORENSICS/MISC |
| A19 | 大数分解（>128-bit 半素数） | 多题依赖 | ✅ yafu sidecar（sha256-pinned） | — |

## 与 CTF2 刷题实践的衔接约定

1. **每轮刷题前**：从本表挑 1–2 个"工具链现状 = 部分/❌"的能力域，到对应
   ground 拉题（`ctf-forge ctf2 practice` → `ctf2 get`），先试现有原语。
2. **解题中**：新的可复用技巧按 SKILL.md 的 Rust-first 规则进 crate 并带
   单元测试；测试向量本地生成（参考 KNOWLEDGE.md 各卡的 vector 记录）。
3. **解题后**：CHALLENGE-LOG.md 记一行（成败都要记，失败记 BLOCKED 原因 +
   缺的工具域编号——用本表编号）。
4. **回归**：crypto 类题的实例参数落 `challenges/<ground>/files/`，作为
   `cargo test` 级别的回归向量（模式见 lattice.rs tests）。

## 2024 决赛 5 题（无题解）行动清单

分析见 `.tmp/赛题分析报告.md` 第 4 章。状态：分析完成，exp 未落地。

| 题 | 链路 | 剩余工作 | 对应能力域 |
|---|---|---|---|
| springboard | fmtstr 16B/轮 → one_gadget | exp 编写（fmtstr builder 已就绪 A13） | A13 |
| ez_exchange | 栈泄露+16B 溢出 → partial overwrite 1/16 循环 → ROP | 循环原语已实测；libc 泄露与收尾 | A11 |
| baby_linklist | No-PIE GOT 写（结构已还原，fault 点待 gdb） | gdb 动调定位 fault | A12 |
| story | UAF+dup → poison .bss → mmap 贴 libc → __free_hook | 端到端 exp（链路已设计到偏移级） | A12+A14 |
| Vegetables | 42B rbp 溢出 → magic RWX → openat2 shellcode | counter=42 已实测；exp 编写 | A11+A14 |
