# KNOWLEDGE — technique cards (primitive-first, no copyrighted writeups)

Each card: technique, preconditions, I/O schema, failure mode, synthetic test
vector (all vectors live in `crates/ctf-crypto/tests/vectors.json`, generated
locally; see `.tmp/vectors.json` generator history in PROGRESS).

## rsa.decrypt — 已知 n, d, c
- Preconditions: d, n, c known (int/0x-hex).
- I/O: `crypto_rsa attack=decrypt params={c,d,n}` → m_dec/m_hex/m_bytes.
- Failure: bit cap (>8192) → `TooLarge` error.
- Vector: vectors.json `from_pq` (m decryptable with derived d).

## rsa.from_pq — p, q 已知(含 gcd(e,φ)>1)
- Technique: φ=(p-1)(q-1); t=gcd(e,φ); t=1 → d=e⁻¹; small t → d'=(e/t)⁻¹,
  m^t=c^{d'} then integer t-th root; large t → per-prime path (partial).
- Failure: non-exact root → `NoRoot{k}` (AMM gap, see CAPABILITIES).
- Vector: `from_pq` (1024-bit n, e=65537).

## rsa.wiener — 维纳攻击
- Preconditions: d < (1/3)·N^(1/4), e·d ≡ 1 mod λ(N).
- I/O: `crypto_rsa attack=wiener params={e,n}` → d.
- Failure: returns None when no convergent validates (normal-d instances).
- Vector: `wiener` (1024-bit n, 130-bit d).

## rsa.fermat — 费马分解(p≈q)
- Preconditions: |p−q| small relative to √N.
- I/O: `attack=fermat` → p·q; then from_pq.
- Failure: None after max_iter.
- Vector: `fermat` (512-bit n, |p−q|=2→small).

## rsa.low_e — 低指数 / Håstad(单模数)
- Preconditions: m^e < n (small e, short m).
- I/O: `attack=low_e` → integer e-th root of c+k·n.
- Failure: None when padding randomizes m.
- Vector: `low_e` (m="hi", e=3).

## rsa.common_modulus — 共模攻击
- Preconditions: same n, two ciphertexts, gcd(e1,e2)=1 (auto-reduces by gcd).
- I/O: `attack=common_modulus params={c1,c2,e1,e2,n}` → m; negative exponents
  handled via modular inverse.
- Vector: `common_modulus` (e1=17, e2=257).

## rsa.hastad — 广播攻击
- Preconditions: same m, small e, ≥e pairwise-coprime moduli.
- I/O: `attack=hastad params={cs[],ns[],e}` → CRT then e-th root.
- Failure: non-coprime moduli → typed error.
- Vector: `hastad` (3×1024-bit moduli, e=3).

## rsa.dp_leak / rsa.dpdq — dp、dq 泄漏
- Technique: e·dp−1 = x·(p−1), x<e → divisor enumeration recovers p;
  dpdq: CRT combine m1=c^dp mod p, m2=c^dq mod q.
- Failure: dp_leak requires e ≤ 2^20 (guard).
- Vector: `dp_leak` (e=5), `dpdq` (256-bit p,q).

## rsa.factor_rho / factor_p1 — 小因子分解
- Preconditions: rho — small factor; p1 — p−1 B-smooth.
- Vector: `pollard_rho` (128-bit), `pollard_p1` (256-bit, smooth p−1).
- Failure: None → escalate to yafu sidecar (`sidecar_run engine=yafu`).

## rsa.shared_prime — 共享素数
- Technique: p = gcd(n1, n2) across moduli.
- Vector: `shared_prime`.

## prng.lcg — LCG 参数恢复与预测
- Techniques: a=(x2−x1)(x1−x0)⁻¹ mod m; b=x1−a·x0; m=gcd(T2,T1) (5 outputs,
  signed diffs); step_back via a⁻¹; seed_search by byte substring.
- Failure: gcd(x1−x0, m)≠1 → inverse error (documented).
- Vector: `lcg` (m=2³¹, glibc params).

## prng.mt19937 — 梅森旋转预测
- Technique: untemper 624 outputs → state; twist reproduces stream.
  CPython-compatible seeding (init_by_array) cross-verified against
  `random.seed(1234)` outputs 0..2 and 624..626.
- Failure: <624 outputs → None.
- Vector: hardcoded in `ctf-crypto/src/mt19937.rs` tests (CPython cross-check).

## codec.carve — magic+序号+长度 雕刻(泥坑采集器形状)
- Technique: scan [magic][u32 seq][u32 len][payload]; reject decoys with
  impossible length (> max_payload or beyond buffer).
- I/O: `filescan op=carve magic=PKT1 endian=big`.
- Vector: unit test in `ctf-codec/src/magic.rs` (valid + decoy container).

## codec.auto — 多层编码剥离
- Order: hex → base64 → base64url → base32 per layer; misfire risk documented
  (pure-alnum %4 strings); flag-shaped/spaced text never misfires.

## hash.sha256 — sidecar 校验
- FIPS 180-4 vectors (`ctf-core/src/hash.rs`); pins tools/yafu/yafu-x64.exe
  sha256=1e125670c6be1b576383924449efe05ded8882cbd924cd362f55de3821143f5e.

## session.ctf2 — 平台 I/O 拓扑
- Official CTF2 MCP (ctf2_get_profile / ctf2_list_daily_challenges /
  ctf2_list_practice_grounds / ctf2_get_practice_challenge) when the session
  advertises it; otherwise auto-ctf Python client + $CTF2_TOKEN (never CTFd
  routes, never admin APIs). 401 → reconnect; 403 → report scope, stop;
  429 → honor Retry-After. Flag submission requires explicit user confirmation
  of the exact flag + challenge (confirmation=true, suite sub_flag_id UUID).


## usb.hid_keyboard — USB 键盘流量分析 (第09章)
- Technique: parse pcapng → extract EPB packets → find 8-byte HID reports
  → track keycode transitions → map to letters via USB HID usage table
- Preconditions: USB HID keyboard capture in pcapng format
- I/O: `parse(fmt=pcap)` → streams + usb_keyboard_decoded
- Failure mode: USB metadata bytes can be mistaken for keycodes if the
  HID report offset is not precisely identified. Need to lock onto the
  specific offset where keycodes appear (challenges use usbpcap format
  where the report is at a fixed offset from the end of each packet).
- Test vector: DASBOOK 第09章 键盘流量分析 (66 packets, keycodes 08/0f/12/1a/15/07 → "elloworld" fragment visible)

## lattice.small_roots — Coppersmith 小根（Rust 原生，2026-09 落地）
- Technique: Howgrave–Graham 构造 g_{i,j} = x^j·f^i·N^max(0,⌈βm⌉−i) + x^i·f^m 尾行；
  列按 X^c 缩放；LLL（δ=3/4，精确有理 G-S，局部 swap 更新）→ 短向量反缩放成
  整数多项式 → 两两有理 GCD + Sturm 序列精确根隔离（squarefree 化处理重根）→
  逐候选验证 gcd(f(x0), n)。
- Preconditions: f 一元整系数（不必 monic，内部 mod n monic 化，需 lead 可逆）；
  根 x0 < 2^x_bits 且 f(x0) ≡ 0 mod b，b|n, b ≥ n^beta。
- I/O: `ctf-forge lattice --op small_roots --params p.json`
  （p.json: {poly:[低→高], n, beta_num, beta_den, x_bits, m, t}）→ {roots:[{x0,factor}]}。
- Failure mode: ① m/t 过小 → HG 界不满足 → gcd 恒为常数 → 返回空（加大 m）；
  ② dim > ~24 时精确有理 LLL 变慢（release 下 dim 23 约 1–2 分钟）；
  ③ 系数必须保留为精确整数——任何 mod n 归约会破坏 beta<1 时 mod p^⌈βm⌉ 的同余
  （n 的倍数只保证 ≡0 mod p）——这是实现里最隐蔽的坑。
- Test vector: lattice.rs tests——beta=1 已知低位（e=3 padding）、beta=1/2 已知高位
  因子分解（p=next_prime(2^160·3+7) 合成实例）；真实验证见 CHALLENGE-LOG 华为杯
  insecure_padding 复跑条目。

## lattice.apbq — apbq/正交格（Rust 化待做，Python+flint 过渡已验证）
- Technique: h_i = a_i·p + b_i·q 型泄露 → 6×6 格 + 权重 W≈x_i 量级 → LLL 得
  (0,0,0,a₁p,a₂p,a₃p) → gcd 分解。
- Vector: work/y2024q/coppersmith.py（华为杯 real_rsa_2 复现，flint LLL）。

## lcg.six_outputs — 六输出盲恢复（华为杯四层挑战 ch4 模式）
- Technique: t_i = x_{i+1}−x_i；t1t3−t2²、t2t4−t3²、t0t4−t1t3 对 N 同余 →
  三者绝对值 GCD = N（可为小倍数）。小倍数剥离：按小素数拆链，从最小候选向上
  找第一个满足完整递推（a·x_i+b ≡ x_{i+1} 连续三点）的模数——提升模（如 2N）
  与数据自洽，必须取最小自洽者。
- I/O: `ctf_crypto::lcg::recover_seed_six(&[x;6])` → (seed, a, b, N)。
- Vector: lcg.rs six_tests（N=2^31−1 合成实例，含 2N 剥离路径）。

## fmtstr.incremental — 预算受限的格式化字符串（2024 决赛 springboard/mips_fmt 模式）
- Technique: `%<pad>c%<K>$hhn` 维护 running counter（mod 256）；pad=0 时输出裸
  `%K$hhn`（printf 语义：%0c 打印 1 字符，必须省略）。地址附在 spec 之后按小端
  拼接；多轮循环（partial overwrite 重入 main）每轮预算 16B。
- I/O: `ctf_pwn::fmtstr::{hhn_spec, spec_chars, IncrementalFmt::{round_hhn, build_oneshot}}`。
- Failure mode: 预算不足返回 None；模拟器（tests::simulate）验证字符计数。
- Vector: fmtstr.rs tests（hello-world 流 + 预算拒绝）。

## hid.keyboard — USB HID 键盘流量解码
- Technique: 8 字节报告 [modifier][reserved][k1..k6]，0→pressed 转沿出字符，
  shift（0x02/0x20）选移位符号，按住去重。USBPcap 场景报告在包尾固定偏移。
- I/O: `ctf_codec::hid::decode_keyboard_reports(&stream, offset, stride)`。
- Vector: hid.rs tests（hello world / 大小写 / 数字行符号 / stride 切片）。
- 注意: usage 表 0x1f='2'、0x20='3'（易错），0x14='q'。

## seccomp.bpf_decode + openat2 — 沙箱黑名单识别与绕过（2024 决赛 Vegetables）
- Technique: 手写 BPF 从内存构造：sock_filter {u16 code, u8 jt, u8 jf, u32 k}；
  0x15=JEQ→KILL(0x80000000)，0x35=JGE，0x06=RET。黑名单含 open(2)/openat(257)
  时用裸 syscall openat2(437)（glibc 2.27 无包装）。
- 配套: magic() 型"第二次调用才 mmap RWX 固定页"的出口设计 → 需 ROP 再调一次。
- Vector: CHALLENGE-LOG Vegetables 条目（counter=42 实测、BPF 逐条解码）。

## heap.calloc_bypass + mmap_adjacent — 2024 决赛 story 套路
- calloc 绕过 tcache 取块（glibc 行为）→ "free 后重插拿回同块" 经典 UAF 失效；
  替代路径: delete 不清指针 + add 数据写覆盖 tcache entry key → dup → 投毒。
- show 无 idx 边界 + `__dso_handle` 自指向 → show(-23) 泄 PIE（实测 ✓）。
- 巨 size malloc → mmap 落在 libc 映射正下方（topdown first-fit）→ edit 从
  mmap 块向 libc 越界写 __free_hook，无需 libc 泄露。

## stack.partial_overwrite_pie — PIE 部分覆盖循环（2024 决赛 ez_exchange）
- 16 字节溢出只够 saved rbp+ret；ret 低 2 字节改写回跳 main 形成无限读写循环。
  成功率 1/16（PIE 低 16 位中 4 位 ASLR + 进位），forkserver/重连爆破。
- 实测: work/y2024f（24 次尝试内验证循环成立）。

## stack.smashing_argv0 — __stack_chk_fail 泄露（2023 easy_ssp）
- 溢出仅达 argv[0] 指针 → 改指 0x602018（No-PIE 固定地址含 libc 指针）→
  主动触发 "*** stack smashing detected ***: " 打印泄露；fork 多轮逐轮利用。

## netauth.ntlmv2_hashcat — AD 流量口令破解（2025 EZ_ATEXEC）
- DCERPC/NTLMSSP 导出 NetNTLMv2 → `hashcat -m 5600 -a 0 hash.txt rockyou.txt`。
- 自造 hash 复现流程: work/y2025r/gen_ntlmv2.py（pycryptodome MD4，首轮位移易错）。
