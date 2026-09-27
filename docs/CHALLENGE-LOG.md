# CHALLENGE-LOG — one row per challenge attempt (distill even on failure)

Platform: CTF2 (https://ctf2.dasctf.com). Session unlock: official MCP absent →
auto-ctf PAT fallback for platform I/O + user-authorized browser session for the
web-only practice-ground challenge enumeration/attachments (`/api/v1/practice/{id}/challenges/`
observed from the page's own XHR; token stays inside the page, never extracted).

## DASBOOK 第06章 (RSA/PRNG teaching set) — 14/15 solved by ctf-forge

| challenge | attack used | result |
|---|---|---|
| [无flag]Rabin攻击 | rabin | 4 roots recovered, correct root verified by squaring |
| [无flag]Wiener攻击 | auto→wiener | m = "do you know wiener attack" |
| [无flag]dpdq泄露攻击 | dp_dq | m = "don't leak your dp&dq" |
| [无flag]dp泄露攻击 | auto→dp_leak→from_pq | m = "don't leak your dp or dq" |
| [无flag]pq过近 | auto→fermat | m = "too close!!!" |
| [无flag]低加密指数广播攻击 | hastad_broadcast (e=66, 10 moduli, CRT+66th root) | m = "crt is cool!!!" |
| [无flag]低加密指数攻击 | auto→low_e | m = "small e and big n!!!" |
| [无flag]共享素数 | shared_prime gcd | p recovered, n=p·q verified |
| [无flag]共模攻击 | common_modulus (e1=65537, e2=123123) | m = "same module attack!!!" |
| [无flag]因数分解 | auto→yafu sidecar (255-bit N) | factors recovered, plaintext verified |
| [无flag]Schemidt_Samoa | schmidt_samoa (N=p²q, d=N⁻¹ mod φ) | m verified |
| [无flag]p-1光滑攻击 | pollard_p1 (B=50k) | factors recovered |
| 伪随机数 | mt19937_predict (624 words → state → next word) | next word 2866792166, md5 candidates computed |
| [SWPU2020]happy | algebraic p-recovery (B·p²−(A+B)·p+B=0) + decrypt | verified flag recovered, FLAG_REDACTED in git |
| [GKCTF_2021]Random | — | BLOCKED: RAR archive parsing (tool gap, domain 11) |

## BUUCTF CRYPTO bulk sweep (861 with files, 606 parsed by generic extractor)

| challenge | attack | result |
|---|---|---|
| _WUSTCTF2020_babyrsa | auto (dp_leak path) | verified flag, FLAG_REDACTED in git |
| _WUSTCTF2020_dp_leaking_1s_very_d@angerous | auto→dp_leak | verified flag, FLAG_REDACTED in git |
| RSA_begin ×3 | auto | recovered_noisy (plaintext not printable — extractor mismatch, needs per-format handling) |
| (remaining ~600) | — | no n/e/c params in raw attachment text: task.py generators, .pem keys, AES/zip containers → per-format parsers are the next-cycle work |

## DASBOOK 第05章 classical ciphers — Rust driver cycle 3

| challenge | attack | result |
|---|---|---|
| 摩斯密码 ×2 | morse_decode | "IWANTTOGETFLAG" |
| 仿射密码 ×2 | affine_decrypt (a=3,b=11) | "an affine cipher can decode with affine decoder…" |
| 维吉尼亚/普莱菲尔/自动密钥 ×6 | autokey/vigenere with readability gate | 自动密钥真解 "testwithautokeycipher"; playfair honestly marked unverified |
| qwe电脑键盘密码 ×2 | qwe_keyboard_decrypt | "flag{FLAG_REDACTED}" family (ysqu→flag verified) |
| 手机键盘密码 ×2 | phone_decode | multi-tap pairs decoded |
| 栅栏密码 | rail_fence_brute (rails 2..9) | candidates emitted |
| 曲路密码 | route_decrypt (5×4 winding) | candidates emitted |

Remaining failures by family: image/audio stego (第07章, needs LSB/EXIF/audio
primitives), pcap analysis (第09章, ctf-parse P1), disk forensics (第10章),
RE (第12章 → reverse-mcp path, BLOCKED_IDA_SDK), puzzle-specific substitution
(猪圈/跳舞的小人 need image mapping).

## BUUCTF CRYPTO fast sweep (cycle 3: PEM + flag.enc support)

pubkey.pem/DER parse (SPKI + PKCS#1) and binary flag.enc -> int ciphertext
added to the Rust driver; bulk --fast disables the sidecar for sweep speed.

| challenge | attack | result |
|---|---|---|
| Final (613 with attachments, full coverage) | auto + PEM + caesar/rail specials | 19 solved (Caesar x4, Vigenere x4, Fibonacci x2, mostlycommon x2, Y1nglish x2, Morse, hill→NO: reclassified, dp_leaking, babyrsa), 4 recovered_noisy, 314 blocked_archive, 276 failed (hill/PEM-2048/stego formats) |

False-positive control: rail-fence candidate filter tightened to literal
flag{/ctf{/dasctf{ hits (Caesar's_Secert + UTCTF2020_hill were initially
mis-solved by a loose shape filter — now caesar_solve resolves the former;
the latter correctly fails awaiting a Hill-cipher primitive).

## Daily challenges (user API only; list view has no files/detail endpoints)

| id | name | category | result |
|---|---|---|---|
| ab19e669-8226-4ef1-b88c-e40e4973a41d | NovaPortal:不死的旧版会话令牌 | WEB | solved (pre-existing) |
| 1220ccd8-b98c-4151-b581-7da403a548cd | 串口探针:从逻辑捕获还原启动日志 | HARDWARE | solved (pre-existing) |
| 5feeae65-6d8f-4a4c-874b-9a88c251cb10 | 遥测横幅与复用的密钥流 | CRYPTO | BLOCKED_ENV (container data; no daily env endpoint in User OpenAPI) |
| 761d0f3b-ef8d-4d13-82c4-afd93890a171 | SHARDLINE 分片重组 | MISC | BLOCKED_ENV |
| 7a658e01-47df-4d93-bd38-95e65baa04db | 泥坑里的采集器:转储雕刻与多层解码 | MISC | BLOCKED_NO_DATA (dump artifact not exposed via API) |
| (other 15) | see docs/QUEUE.json | mixed | BLOCKED_ENV/BLOCKED_NO_DATA |

## Practice grounds — enumeration status

| ground | count | with files | notes |
|---|---|---|---|
| DASBOOK | 92 | 81 | 第05-06章 archived + solved; 07-13 chapters queued |
| N1BOOK | 46 | 23 | CRYPTO/MISC chapters archived |
| BUUCTF | 5857 | CRYPTO 861/921, MISC 911/970 | CRYPTO attachments downloaded + swept; MISC downloading |
| BUUCTF-Real | 278 | 0 | container-based CVE set |
| BUUCTF-Basic | 36 | 0 | container-based |
| AWD 练习场 | 3 | — | out of scope (no unsolicited AWD) |

## 华为杯研究生赛 59 题全量分析（2026-09）— 能力基线

59 题（2022–2025 + 研发赛道）全部分析；报告 `.tmp/赛题分析报告.md`，能力矩阵
`docs/COMPETENCY.md`。实测复现 19 题、关键原语级实测 ~15 题。本次沉淀的
新 primitive：`lattice --op small_roots`（Coppersmith，纯 Rust）、
`lcg::recover_seed_six`、`ctf-pwn::fmtstr`、`ctf-codec::hid`。

| 成果 | 说明 |
|---|---|
| 2024 决赛 5 Pwn 无题解缺口填补 | Vegetables（42B rbp 溢出+openat2 seccomp）、story（UAF+OOB show 泄 PIE+mmap 贴 libc）、ez_exchange（16B partial overwrite 循环实测 1/16）、baby_linklist（结构还原）、springboard（16B fmtstr）|
| crypto 复现 | EZ_RSA_5 / insecure_padding / real_rsa_2 → DASCTF flags；downcity VM 爆破、ezhtml WASM |
| 后续 | 决赛 exp 落地（COMPETENCY 行动清单）；baby_linklist gdb 定位 fault |

## insecure_padding Rust Coppersmith 复跑（2026-09）

p=1000bit/q=536bit 合成实例（beta=2/3 近似 1000/1536，X=2^160，m=5, t=8，dim 23）：
`ctf-forge lattice --op small_roots`（release）运行中/已完成，结果见
`.tmp/work/cli_smoke/ip_result.json`；对照 Python+flint 版 work/y2024q/coppersmith.py。

## CTF2 真实赛题取证验证（2026-09）— 101 pcap 批量扫 + DNS exfil + 磁盘 memscan

用新落地的 `forensics` CLI 六操作对 CTF2 平台归档的 **101 个真实 pcap/pcapng**
做了批量验证 + 深度分析。

### 批量 pcap 扫描 — 99/101 解析成功 (98%)

| 指标 | 数量 |
|---|---|
| 解析成功 | 99 |
| 解析失败 | 2（CTF 故意改魔数 0xa1b2cd34 — 已加支持） |
| DNS 命中 | 14 题（含 3904 条的 DNS 隐蔽通道） |
| HID 键盘命中 | 15 题 |
| 最大 pcapng | 111,722 包（手把天尊） |

### DNS 隐蔽通道提取 — stealer 挑战

`stealer` (BUUCTF): 3904 条 DNS 消息，1944 个 query 子域藏 base64 编码的
PNG 图像。提取流程: 过滤 query → 取子域 → 拼 base64 → 去 `.`/`*` 分隔符 →
解码 → **81750 字节 PNG 完整提取** ✓（`.tmp/work/cli_smoke/stealer_extract.png`）。

### 磁盘镜像 memscan — XMAN2018

`_XMAN2018排位赛_file/fc2cc2aa.img` (10MB ext4): `forensics --op memscan`
UTF-16LE 雕刻直接命中 **`flag{fugly_cats_need_luv_2}`** @0x900400 ✓
（rawmem 模块的 UTF-16LE 雕刻 + flag 候选搜索）。

### pcap 魔数变体支持

- `0xa1b2c3d4` 标准 + `0xa1b23c4d` 纳秒 + **`0xa1b2cd34` CTF 变体**（新增）
- 修正: pcap 头魔数笔误 0xa1b1_2c3d → 0xa1b2_c3d4（之前的 pcap 文件全部无法解析）

### HID 键盘解码 — 手把天尊 (BUUCTF)

111,722 包 pcapng → USB HID 解码输出 6072 字符键盘流。含 A-Z 字母扫描噪声，
flag 需题目特定的键盘布局映射（ capability gap 记录 → A6 后续工作）。

### 能力验证结论

| 域 | 验证方式 | 结果 |
|---|---|---|
| 流量解析 | 101 真实 pcap | 99% 成功率 |
| DNS 解码 | stealer DNS exfil | 3904 条全解码, PNG 提取 ✓ |
| 内存雕刻 | XMAN 磁盘镜像 | flag 直接命中 ✓ |
| HID 解码 | 手把天尊 111k 包 | 6072 字符提取 ✓（布局映射待做） |
| pcap 魔数 | tele.pcap 0xa1b2cd34 | 新增支持 ✓ |
