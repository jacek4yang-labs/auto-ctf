# -*- coding: utf-8 -*-
"""Build four self-contained role training packages (zip) for the ctf2 platform.

Each zip: 训练手册.md (knowledge + grind lists by direction, no week schedule,
no workspace coupling — challenges are found on ctf2 by exact name) +
赛题分析报告-参考.md (target-competition analysis, flags redacted).
"""
import json, os, re, zipfile, random
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
cat = json.load(open(os.path.join(HERE, 'catalog.json'), encoding='utf-8'))

# ---------------------------------------------------------------- helpers
DIFF_RANK = {'Easy': 0, 'Middle': 1, 'MIDDLE': 1, 'Normal': 1, 'Medium': 1,
             'Hard': 2, 'HARD': 2, 'Difficult': 3, 'Hell': 4}

used = set()

def ground_pool(catname):
    return [x for x in cat if x['category'] == catname]

def dasbook_pool(chapters):
    return [x for x in cat if x['ground'] == 'dasbook'
            and any(c in x['category'] for c in chapters)]

def n1book_pool(chapters):
    return [x for x in cat if x['ground'] == 'n1book'
            and any(c in x['category'] for c in chapters)]

def pick(bucket, n):
    kws = [k.lower() for k in bucket['kw']]
    pool = bucket['pool']
    hits, rest = [], []
    for x in pool:
        if id(x) in used:
            continue
        nm = x['name'].lower()
        (hits if any(k in nm for k in kws) else rest).append(x)
    src = hits if len(hits) >= n else hits + rest
    picked = []
    for x in src:
        if len(picked) >= n:
            break
        if id(x) in used:
            continue
        used.add(id(x))
        picked.append(x)
    picked.sort(key=lambda x: (DIFF_RANK.get(x['difficulty'] or '', 1), x['name'].lower()))
    return picked

def table(bucket, n):
    rows = pick(bucket, n)
    lines = [f"### {bucket['title']}（{len(rows)} 题）", "",
             f"**本方向达标要求**：{GOALS.get(bucket['title'], '')}", "",
             "| # | 平台题名（在 ctf2 练习中心搜索） | 难度 |", "|---|------|------|"]
    for i, x in enumerate(rows, 1):
        lines.append(f"| {i} | {x['name'].replace('|','/')} | {x['difficulty'] or '—'} |")
    return '\n'.join(lines) + '\n'

# ---------------------------------------------------------------- grind buckets
A_buckets = [
    dict(title='A1 环境与栈基础（识别→溢出→ret2libc）', n=30,
         kw=['babystack', 'stack', 'bof', 'overflow', 'ret2', 'level', 'warmup', 'pwn1', 'hello', 'ciscn_2019_c', 'test_your_', 'when_did_you'],
         pool=ground_pool('PWN') + dasbook_pool(['第15章'])),
    dict(title='A2 ROP 与栈迁移', n=14,
         kw=['rop', 'gadget', 'migrate', 'srop', 'leave', 'csu', 'move', 'finall', 'borrow'],
         pool=ground_pool('PWN') + dasbook_pool(['第15章'])),
    dict(title='A3 格式化字符串', n=12,
         kw=['fmt', 'format', 'playfmt', 'printf'],
         pool=ground_pool('PWN') + dasbook_pool(['第15章'])),
    dict(title='A4 堆利用 glibc2.23（fastbin/unsorted/UAF/unlink）', n=24,
         kw=['heap', 'babyheap', 'note', 'uaf', 'fastbin', 'unlink', 'freenote', 'book', 'babyfeng', 'magicheap'],
         pool=ground_pool('PWN') + dasbook_pool(['第16章'])),
    dict(title='A5 堆利用 glibc2.31（tcache）与泄露链', n=16,
         kw=['tcache', 'children', 'tear', 'hole', 'yellow', 'iron', 'one_gadget', 'libc', 'leak', 'hijack'],
         pool=ground_pool('PWN')),
    dict(title='A6 ORW / shellcode / 沙箱', n=14,
         kw=['orw', 'shellcode', 'seccomp', 'sandbox', 'shell', 'execve'],
         pool=ground_pool('PWN')),
    dict(title='A7 异构与内核（MIPS / driver，选学一项）', n=10,
         kw=['mips', 'driver', 'kernel', 'arm', 'qemu'],
         pool=ground_pool('PWN') + ground_pool('REVERSE') + dasbook_pool(['第17章'])),
]

B_buckets = [
    dict(title='B1 PHP 审计与绕过（弱比较/解析/反序列化/执行/随机数）', n=30,
         kw=['php', 'unserialize', 'md5', 'weak', 'strcmp', 'include', 'upload', 'bypass', 'wakeup', 'think', 'laravel', 'eval', 'filter', 'rce', 'webshell'],
         pool=ground_pool('WEB')),
    dict(title='B2 SSRF 与内网二次利用（gopher/Redis/Memcached）', n=16,
         kw=['ssrf', 'redis', 'gopher', 'curl', 'url', 'memcached', 'proxy', 'intranet', '内网'],
         pool=ground_pool('WEB')),
    dict(title='B3 SQL 注入（报错/盲注/绕过）', n=14,
         kw=['sql', 'inject', 'sqli', 'blind', 'quine', 'login', 'db'],
         pool=ground_pool('WEB')),
    dict(title='B4 Java / 反序列化 / RPC', n=16,
         kw=['java', 'jaba', 'javalib', 'spring', 'hessian', 'jndi', 'rmi', 'deser', 'deserialize', 'shiro', 'log4j', 'easyjaba', 'easyjaba'],
         pool=ground_pool('WEB')),
    dict(title='B5 鉴权与会话（JWT/cookie/模板注入/SSTI）', n=12,
         kw=['jwt', 'token', 'session', 'cookie', 'auth', 'ssti', 'flask', 'jinja', 'pickle', 'node', 'express', 'template', 'render'],
         pool=ground_pool('WEB')),
    dict(title='B6 综合组合拳（限时 40 分钟/题）', n=20,
         kw=['calc', 'shop', 'game', 'index', 'checkin', 'cool', 'go', 'proxy', 'easy_web', 'baby_web', 'ez_'],
         pool=ground_pool('WEB')),
]

C_buckets = [
    dict(title='C1 RSA 基础攻击（e=3/共模/广播/dp/Fermat/Wiener/互逆元）', n=30,
         kw=['rsa', 'wiener', 'fermat', 'broadcast', 'common', 'dp', 'hastad', 'rabin'],
         pool=ground_pool('CRYPTO') + dasbook_pool(['第06章'])),
    dict(title='C2 格与 Coppersmith（已知高位/低位/不平衡 n/正交格）', n=14,
         kw=['copper', 'lattice', 'boneh', 'durfee', 'stereotyped', 'partial', 'padding', 'leak', 'small', 'unlock'],
         pool=ground_pool('CRYPTO')),
    dict(title='C3 PRNG / LCG（全部手写还原，不现场推）', n=14,
         kw=['lcg', 'rand', 'random', 'mt19937', '伪随机', 'predict', 'seed', '四层'],
         pool=ground_pool('CRYPTO') + dasbook_pool(['第06章'])),
    dict(title='C4 其他密码（AES/Rabin/ECC/古典/dasbook 教学链）', n=16,
         kw=['aes', 'des', 'rc4', 'rabin', 'ecc', 'elliptic', 'hill', 'affine', 'vigenere', 'playfair', 'fence', 'morse', 'md5', 'hash'],
         pool=ground_pool('CRYPTO') + dasbook_pool(['第05章'])),
    dict(title='C5 REVERSE：VM / WASM / .NET / PYC / APK', n=16,
         kw=['vm', 'wasm', 'dotnet', 'pyc', 'python', 'apk', 'java', 'kotlin', 'crackme', 'key', 'net'],
         pool=ground_pool('REVERSE') + dasbook_pool(['第12章']) + n1book_pool(['第05章', '第04章'])),
    dict(title='C6 REVERSE：花指令/反调试/SMC 与算法还原', n=12,
         kw=['花指令', 'smc', '反调试', 'maze', '迷宫', 'z3', 'angr', 'sudoku', '约束', 'game', 'baby_rev', 're1', 're2'],
         pool=ground_pool('REVERSE') + dasbook_pool(['第13章'])),
]

D_buckets = [
    dict(title='D1 编码全家桶与古典密码（开赛武器）', n=20,
         kw=['base', 'encode', 'morse', '键盘', 'zero', 'unicode', 'charset', 'code', 'password', 'cipher', '奇怪的', 'e_e'],
         pool=ground_pool('MISC') + dasbook_pool(['第05章'])),
    dict(title='D2 图片隐写（LSB/宽高/盲水印/附加数据/二维码）', n=22,
         kw=['steg', 'lsb', 'png', 'gif', 'jpg', 'img', 'watermark', '盲水印', '宽', 'picture', 'photo', 'qrcode', '二维码', 'qr'],
         pool=ground_pool('MISC') + dasbook_pool(['第07章'])),
    dict(title='D3 ZIP 与文件攻击（伪加密/CRC32/字典/掩码）', n=14,
         kw=['zip', 'crc', '压缩', 'rar', '加密的', 'pass'],
         pool=ground_pool('MISC') + dasbook_pool(['第08章'])),
    dict(title='D4 流量分析（HTTP/TLS/USB 键盘鼠标/webshell 流量）', n=18,
         kw=['pcap', 'usb', 'keyboard', 'mouse', '流量', 'http', 'tls', 'wifi', 'network', 'hid', '端口'],
         pool=ground_pool('MISC') + dasbook_pool(['第09章'])),
    dict(title='D5 音频与文档隐写（MP3/频谱/波形/PDF/Word）', n=12,
         kw=['mp3', 'wav', 'audio', '频谱', '声音', 'music', 'pdf', 'word', 'doc', '文档'],
         pool=ground_pool('MISC') + dasbook_pool(['第07章'])),
    dict(title='D6 取证与长链（内存/磁盘/NTLM→AES 流程）', n=14,
         kw=['mem', 'memory', 'forensi', 'disk', 'ntlm', 'kerbero', '取证', 'vmdk', 'e01', '镜像'],
         pool=ground_pool('MISC') + dasbook_pool(['第10章'])),
]

# ---------------------------------------------------------------- goals (per direction)
GOALS = {
 'A1 环境与栈基础（识别→溢出→ret2libc）': '先用 file/checksec 摸清保护；溢出长度精确算；puts@plt+got 泄 libc → system("/bin/sh")。前 10 题允许查资料，之后不看资料打通。',
 'A2 ROP 与栈迁移': 'ret 对齐、__libc_csu_init、leave;ret 迁 bss、SROP；把通用片段沉淀成自己的 exp 模板。',
 'A3 格式化字符串': '%p 找偏移、%hn/%hhn 写 got；无限输入的标准 fmt 全部打通，再挑战单次写入的题。',
 'A4 堆利用 glibc2.23（fastbin/unsorted/UAF/unlink）': '每题先数 add/delete/edit/show 配额和 size 限制；unsorted bin 泄 libc；fastbin attack 打 __malloc_hook/__free_hook。',
 'A5 堆利用 glibc2.31（tcache）与泄露链': 'tcache 投毒 + key 绕过；配额不够填 tcache 时找题目给的泄露（越界 show/格式化/礼物函数），不死磕 unsorted。',
 'A6 ORW / shellcode / 沙箱': 'seccomp-tools dump 先看禁了什么；写出最短 ORW ROP，不依赖 /bin/sh；ascii_shellcode 会压缩。',
 'A7 异构与内核（MIPS / driver，选学一项）': '选学一项就够：MIPS 大端 ret2libc，或 babydriver 型 cred UAF。',
 'B1 PHP 审计与绕过（弱比较/解析/反序列化/执行/随机数）': '能按数据流复述每条链：入口→过滤→sink；弱比较/0e、parse_url 畸形、unserialize magic 全部本地验证过一遍。',
 'B2 SSRF 与内网二次利用（gopher/Redis/Memcached）': '独立写出 gopher POST 生成器（Content-Length、CRLF、双重 URL 编码）；Redis 未授权写 shell 全流程走通一次。',
 'B3 SQL 注入（报错/盲注/绕过）': '手注出库名表名；空格/引号/关键字绕过有预案；时间盲注报文生成器提前写好。',
 'B4 Java / 反序列化 / RPC': '先认协议再动手（TCP 4 字节长度前缀 + Hessian2）；Hessian2 gadget 链能改模板跑通；shiro/log4j 特征背熟。',
 'B5 鉴权与会话（JWT/cookie/模板注入/SSTI）': 'JWT 三种改法（RS256→HS256、none、kid）+ SSTI 通用 payload 背熟。',
 'B6 综合组合拳（限时 40 分钟/题）': '每题限时 40 分钟：先认语言/框架 → 扫路径看报错 → 审计，写出 3 行下一步计划再动手。',
 'C1 RSA 基础攻击（e=3/共模/广播/dp/Fermat/Wiener/互逆元）': '全部收进 rsa_util.py：输入参数自动判型；每题把攻击式子独立推导一遍再写代码。',
 'C2 格与 Coppersmith（已知高位/低位/不平衡 n/正交格）': '合成参数能解、真题参数能解，2 分钟内出根；格维度和权重自己会设，不只调包。优先 Python + python-flint，Sage 备份。',
 'C3 PRNG / LCG（全部手写还原，不现场推）': 'solve1–4 写成四个函数（已知a,b,N逆推seed / 未知b / 模逆求a / 高阶差分+GCD求N），随机实例全部还原；MT19937 untemper 手写一遍。',
 'C4 其他密码（AES/Rabin/ECC/古典/dasbook 教学链）': '判型优先：拿到密文先跑识别（二次剩余/分组长度/熵）；dasbook 教学题当热身当天做完。',
 'C5 REVERSE：VM / WASM / .NET / PYC / APK': '先列 opcode 表再跑通已知输入；wasm 用 wasm2c；.NET 用 dnSpy；每个 VM 题都产出一份解释器代码。',
 'C6 REVERSE：花指令/反调试/SMC 与算法还原': '看到 75 03 74 01 类先 patch 再反编译；格盘/DP/迷宫还原规则后直接写求解器，不要动态调一整天。',
 'D1 编码全家桶与古典密码（开赛武器）': '20 分钟内给出下一层文件；每种编码认得出特征（b32 字符集、morse 音、零宽字符、大小写比特）。',
 'D2 图片隐写（LSB/宽高/盲水印/附加数据/二维码）': '固定检查顺序：宽高→LSB→通道分离→附加段→盲水印；二维码定位符缺失会修复；工具链不假手他人。',
 'D3 ZIP 与文件攻击（伪加密/CRC32/字典/掩码）': '伪加密秒修；CRC32 短内容碰撞脚本化；rockyou 字典流程肌肉记忆。',
 'D4 流量分析（HTTP/TLS/USB 键盘鼠标/webshell 流量）': '协议分层→跟踪流→导出对象三板斧；USB HID 键盘还原独立完成一次。',
 'D5 音频与文档隐写（MP3/频谱/波形/PDF/Word）': '频谱图/波形图都看一遍再下结论；文档隐写检查注释、隐藏文字、附录。',
 'D6 取证与长链（内存/磁盘/NTLM→AES 流程）': 'NTLMv2 导出→hashcat→解密下一层按清单走；知道下一层证据在哪种工件里。',
}

# ---------------------------------------------------------------- knowledge lists (week-free, complete)
LEARN = {
 'A': """1. **环境与识别（最先练，否则后面全假）**：file/checksec/readelf -d/ldd：PIE、Canary、NX、RELRO、动态链接的 libc 版本；patchelf + glibc-all-in-one（至少 2.23、2.27、2.31 三套）；pwninit、pwntools 模板（连远程、收交互、context.binary）；pwndbg 或 gef：看栈、看堆、下断在 read/malloc/free。菜单题：先数 add/delete/edit/show 的次数和 size 限制，再谈漏洞。
2. **栈利用**：溢出长度精确算（buf、saved rbp、ret）；leave;ret 栈迁移到 bss；ret gadget 对齐（Ubuntu 18+ 需要）；泄 libc：puts@plt + got，算偏移；one_gadget 约束怎么验证，不行就 ORW；partial overwrite：只改返回地址低 2 字节跳回 main（2024 决赛 ez_exchange 的思想，初赛偶有简化版）。
3. **堆利用（分版本记，不要混）**：glibc 2.23——fastbin 单/双链、double free、unsorted bin 泄 libc、打 __malloc_hook/__free_hook；glibc 2.31——tcache 7 个、key 检测、UAF（delete 不清指针）、tcache 投毒到 hook 或已知 bss；配额不够填满 tcache 时不要死磕 unsorted，改找题目给的泄露（越界 show、格式化、礼物函数）。
4. **格式化字符串与沙箱**：%p 泄栈/libc，%n/%hn/%hhn 写；先会无限输入的标准 fmt，再练预算受限型（决赛 springboard 是 16 字节/轮）；seccomp-tools dump：禁 execve 就走 open/openat + read + write；会写最短 ORW 的 ROP，不依赖 /bin/sh。
5. **加分项（最后学，学一项就够）**：内核——babydriver 型：ioctl 改对象大小、cred UAF、改 uid（对应 HRPUAF.ko 一类）；异构——MIPS 大端、qemu-user-static、无 NX 时 fmt 写栈 shellcode。""",
 'B': """1. **PHP 审计与绕过（按数据流记，不按题型名词记）**：比较——`==` 弱比较、0e md5、数组绕 strcmp；解析——parse_url 畸形（`http://///`）、basename、pathinfo；过滤——preg_replace 残留、黑名单关键字、intval 截断；执行——create_function、eval、assert、preg_replace /e（老环境）；随机——mt_srand(时间戳前缀) → 预测 mt_rand；反序列化——unserialize + 常见 magic（__destruct/__wakeup/__toString）。
2. **SSRF 与内网二次利用**：file://、dict://、gopher://；gopher 打 HTTP POST：Content-Length、CRLF、双重 URL 编码；打 Redis / FastCGI / Memcached（CRLF 注入）；回环限制：127.0.0.1、0.0.0.0、[::]、域名指向 127、nip.io；时间盲注挂在 SSRF 后面时，先把报文生成器写对，再谈注入。
3. **鉴权与语言特性**：JWT——RS256 公钥当 HS256 secret、none、kid 注入（出现再查）；Java hashCode 短碰撞（babyql）；Node——模板注入、file:// + pathname 编码、原型链（出现再补）；Python——SSTI、沙箱绕过（出现再补）。
4. **Java / RPC（2025 已考，主线）**：认协议——TCP 4 字节长度前缀 + Hessian2，不是普通 HTTP；入口——XXL-RPC、Motan、gRPC-Web 代理；利用方向——Hessian2 反序列化 → 已知 gadget（Rome 等）→ JNDI；gRPC-Web——`target=` 绕 http(s) 前缀，base64 打内网。能抓到报文、能改模板 payload、能解释为什么是这条链即可，不必从零造 gadget。
5. **代码审计习惯（给源码时固定顺序）**：① 路由和入口参数；② 搜 `eval|system|exec|passthru|popen|unserialize|file_get_contents|curl|include|create_function`；③ 过滤函数怎么写、在哪一层；④ 有没有二次渲染、有没有内网接口。""",
 'C': """1. **数论与 RSA 基础**：模逆、CRT、欧拉函数、阶；e=3 开立方、明文填充太短；共模不同 e、共 e 广播 + CRT；dp/dq 泄露拆 n；互逆元/线性式：`px+qy=n+1` 那类（EZ_RSA_5）；相邻素数、Fermat 分解。
2. **格与 Coppersmith**：LLL 在干什么（直观即可）；Howgrave-Graham + 已知高位/低位；不平衡 n（p ≈ N^{2/3}）；apbq / 正交格：会设维度和权重。实现优先 Python + python-flint，Sage 作备份；输入 n,c,e,已知位数，输出根。
3. **PRNG / LCG（必须手写，不要现场推）**：一层——已知 a,b,N 逆推 seed；两输出未知 b；三输出求 a（模逆）；高阶差分 + GCD 求 N（2022「四层挑战」ch4）。solve1–4 写成四个函数，随机实例全部还原 seed。
4. **其他密码（知道判题即可）**：二次剩余 / Rabin；Goldwasser-Micali 位加密；EC——只到"复合阶 + 错误点加再 GCD"的阅读级，现场 40 分钟没式子就挂。
5. **逆向：VM / WASM / .NET / 算法还原**：自研 VM——先列 opcode 表，再用已知输入跑通，再爆破或 Z3；坑——操作数宽度（downcity 是 word>>8）、AND/OR 写反、条件跳转方向；WASM——wasm2c 或直接读，环形异或从尾逆推（ezhtml）；.NET——dnSpy，注意 Assembly.Load；花指令——看到 `75 03 74 01` 这类先 patch 再反编译（A 可以帮忙打补丁）；格盘/DP/迷宫——还原规则后直接写求解器，不要动态调一整天（50x50 DP、迷宫+LZSS 都考过）。""",
 'D': """1. **编码与文件（开赛武器，最先练熟）**：进制与编码——hex、b32、b58、b64、b85、uu、xx、morse、零宽、大小写比特（E/e）；文件——file、binwalk、foremost、PNG 头 `89 50 4E 47`、ZIP 伪加密；二维码——定位符缺失、用 qrcode/zbar 批量；隐写——LSB、stegsolve、steghide、附录 zip。
2. **流量分析**：Wireshark——按协议分层、跟踪流、导出对象；HTTP 重组、WebSocket、USB HID 键盘映射（神秘端口）；看到 NTLMSSP / Kerberos / SMB / DCERPC 立刻走 Windows 长链的前半。
3. **Windows / AD 向长链（2025 出现 0 解题，按步骤记，每步对应一个工具）**：① pcapng 里找 NTLMSSP → 导出 NetNTLMv2；② hashcat `-m 5600` + rockyou（或弱口令集）；③ 用密码解密 DCERPC / 后续层；④ 计划任务 XML（注意 utf-16le）；⑤ AES-CBC（key/IV 在题面或 XML 里）；⑥ 自研流密码（记录"每字节几轮、有无密文反馈"）；⑦ Kerberos keytab、SMB2 session key **大小端**；⑧ 图片再隐写。
4. **取证短链**：内存——先找进程列表、浏览器、密码框、cmdline；places.sqlite、USB 数位板坐标、VeraCrypt + keyfile；不要求会写插件，要求知道下一层证据在哪种工件里。
5. **调度与平台（这是岗位本身）**：测试日——全员能登、能交、flag 格式确认、附件能下；赛时——唯一提交人、记录每题首次提交时间；共享文档每题一行；盯榜——某题解出数突然涨，喊对应负责人；赛后 WP 骨架——题名、附件哈希、命令、payload。
6. **轻量支援（会用就行）**：hashcat / john 的常见 mode；按 B 给的字典爆破 HTTP；按 A 给的命令跑远程连通测试。""",
}

# ---------------------------------------------------------------- target-competition intel (from 赛题分析报告)
INTEL = {
 'A': """- **难度走向**：2022 栈迁移教学局 → 2023 带完整 Docker/xinetd 环境交付、glibc 版本敏感（2.23/2.31 并用）→ 2024 初赛异构（MIPS32 大端无 NX）+ 内核（Linux 4.4.72 babydriver 型 UAF + AF_PACKET 网络后门双模块）→ 2024 决赛 5 题全部完整攻击链、没有签到题。**内核与 seccomp/openat2 是 2024 的分水岭考点**。
- **决赛五题画像（目标比赛风格）**：

| 题目 | glibc | 保护 | 难度 | 漏洞本质 / 设计好的出口 |
|---|---|---|---|---|
| springboard | 2.23 | PIE+Full RELRO | ★★ | 格式化字符串，每轮仅 16 字节、无限轮——预算管理 |
| ez_exchange | 2.31 | PIE+Full RELRO | ★★☆ | 16 字节溢出恰好 rbp+ret——partial overwrite 建立循环 |
| baby_linklist | 2.31 | **No-PIE**+Partial | ★★★ | 链表删除语义缺陷（free 的是 next 元素）；calloc 绕 tcache；预期出口是无泄露打 GOT/hook |
| story | 2.31 | PIE+Full+Canary | ★★★★ | UAF + 唯 show 无边界检查泄 PIE + mmap 大块贴 libc 写 __free_hook |
| Vegetables | 2.27 | PIE+Full | ★★★★☆ | 游戏得分控制溢出长度、seccomp 连 open/openat 都禁——逼 raw syscall openat2 + RWX 页 shellcode |

- **出题套路**：每题都设计一个"不常规的出口"；**配额/预算管理是决赛主旋律**；glibc 梯度 2.23→2.27→2.31 考察面完整；libc 全部随题给出。
- **训练落点**：日常刷题就按"先数配额→找泄露出口→算预算"的顺序做，和决赛节奏一致。""",
 'B': """- **难度走向**：2022 Node/Java 表达式注入（babyql：Java hashCode 短碰撞 + QLExpress + Nashorn 绕黑名单；HackThisBox：JWT RS256/HS256 混淆 + file:// + nodemon RCE；CSP report-uri 请求伪造）→ 2023 云原生（easyspark：Spark SQL reflect → 云 metadata → K8s serviceaccount token）+ Bad_Memcached（PHP POP 链 + Memcached CRLF 注入 + curl SSRF 串联）→ 2024→2025 Java 反序列化面（XXL-RPC / Motan，TCP 4 字节长度前缀 + Hessian2）。
- **稳定复现的组合**：SSRF + gopher + 内网二次利用（ssssrf 型：gopher 伪造 POST + 仅 127.0.0.1 可达的时间盲注）几乎年年有变体。
- **PHP 没有丢**：very_easyphp 一条链串起 parse_url 畸形、md5 0e、mt_srand 预测、intval 截断、preg_replace 残留、create_function 一句话——说明"PHP 套娃链"仍是基础盘。
- **通用**：决赛/难题都会设计「不常规的出口」——卡住时换思路找出口，不要硬刚常规流程。
- **flag 风格**：2022-2023 偏 md5 hex；2024 起统一 `DASCTF{leet_英文}`；动态题 flag 随环境变化。""",
 'C': """- **难度走向**：2022 LCG 手工数学（四层挑战：ch1 已知 a,b,N 逆推 → ch4 六输出二阶差分 + GCD 求 N）→ 2023 Coppersmith/EC 组合（next-prime 相邻素数 + 已知高位；Step_By_step 分段组合；EC_Party 复合阶 + 错误点加 GCD）→ 2024 正交格 apbq + 不平衡素数（real_rsa_2：6×6 格 + 权重一步 LLL；insecure_padding：p≈N^{2/3} 的 Coppersmith 已知低位）。**Sage 依赖逐年加重，但已验证纯 Python（python-flint LLL）可替代 Sage 完成 Coppersmith 类题**。
- **Reverse 常青考点是 VM**：2022 infantvm（angr）→ 2024 downcity（12 opcode 栈机，操作数 word>>8，真实语义 OR 非 AND，逐字符爆破 30 轮）→ 2024 ezhtml（WASM，环形异或从尾逆推）。还有 50×50 网格 DP、花指令 patch + LZSS 解压迷宫。
- **通用**：决赛/难题都会设计「不常规的出口」——逆向卡住时回头找设计好的出口（弱比较、可跳过的校验、爆破友好的结构），不要硬刚。
- **结论**：把 LCG/Coppersmith 做成队内库（输入自动判型），VM 题产出解释器代码——这是本岗位的"军备"。""",
 'D': """- **难度走向**：取证链越拉越长——2024 内存 → SQLite → USB 数位板坐标 → VeraCrypt 四级；2025 出现 0 解题的 Windows/AD 长链（NTLMSSP → hashcat -m 5600 → DCERPC → 计划任务 XML(utf-16le) → AES-CBC → 自研流密码 → keytab/SMB2 session key 大小端 → 图片再隐写）。
- **稳定复现的题型**：编码（奇怪的E：E/e 大小写比特）、分段小解码（A_Small_Secret：b32 段 + AES + docx document.xml）、二维码（loopQR 信道隐写 + pyzbar 批量；unnamed_qrcode_stego 定位符修复 + PNG 头修复 + hex）、USB HID 键盘（神秘端口）。
- **区块链溯源是 2024 特色**（依赖在线链，赛题复现性差，会流程即可不深钻）。
- **通用**：决赛/难题都会设计「不常规的出口」——长链卡住时回头检查哪一步其实留了后门（弱口令、泄漏文件、可跳过的校验）。
- **Misc 的胜负手在速度**：签到不留、长链把材料交接清楚——你决定全队前 90 分钟的分数。""",
}

# ---------------------------------------------------------------- acceptance (must-do platform challenges)
ACCEPT = {
 'A': [('springboard', '2024 决赛', '16 字节预算的无限格式化字符串，当阅读材料+亲手打通'),
       ('ez_exchange', '2024 决赛', 'partial overwrite 低 2 字节回 main 建立循环'),
       ('baby_linklist', '2024 决赛', 'No-PIE/Partial RELRO 出口 + calloc 绕 tcache 的删除语义缺陷'),
       ('story', '2024 决赛', '只学「UAF + 越界 show 泄 PIE」两步，不必复现整条 mmap 链'),
       ('Vegetables', '2024 决赛', 'seccomp ORW：raw syscall openat2 + RWX 页 shellcode（最难，压轴）'),
       ('stack', '2022 初赛', '纸面也要走完整条链：栈迁移 bss → ret2libc → one_gadget'),
       ('stack_and_heap', '2022 初赛', '重点走栈迁移段'),
       ('cancanneed_new', '2023/2024', '交互复杂的完整堆链'),
       ('easy_ssp', '2023 初赛', 'stack smashing 泄固定地址 → libc → fork 逐轮 one_gadget'),
       ('mips_fmt', '2024 初赛方向', '有时间再碰：MIPS 大端 fmt'),
       ('kernel-network (HRPUAF.ko)', '2024 初赛方向', '内核 babydriver 型：ioctl 改对象大小、cred UAF、改 uid')],
 'B': [('very_easyphp', '2024 初赛', '整条 PHP 套娃链能讲清楚，本地能验证的步骤全部验证'),
       ('ssssrf', '2024 初赛', '独立写出 gopher POST 生成器（双重编码 + CRLF）'),
       ('Bad_Memcached', '2023 初赛', 'PHP POP 链 + Memcached CRLF 注入 + curl SSRF 怎么串，讲清楚'),
       ('babyql', '2022 初赛', 'Java hashCode 短碰撞 + 表达式注入绕黑名单'),
       ('HackThisBox', '2022 初赛', 'JWT RS256/HS256 混淆 + file:// + nodemon RCE'),
       ('easyeval', '2023 初赛', 'parse_url 解析差异 + file:// + RCE'),
       ('startschool', '2023 初赛', 'XSS to RCE，express-art-template 模板注入'),
       ('easyspark', '2023 初赛', 'Spark SQL reflect → 云 metadata → K8s token（了解即可）')],
 'C': [('EZ_RSA_5', '2024 初赛', 'px+qy=n+1 互逆元/线性式：g=gcd(x-1,y-1) 枚举 p=p0+j·b'),
       ('real_rsa_2', '2024 初赛', 'apbq 正交格：6×6 格 + 权重一步 LLL → gcd 得 p'),
       ('insecure_padding', '2024 初赛', 'Coppersmith 已知低位（p≈N^{2/3}）：2 分钟内出根'),
       ('四层挑战 ch1–ch4', '2022 初赛', 'LCG 逐层还原，写成 solve1–4 四个函数，随机实例全部还原'),
       ('downcity', '2024 初赛', '自己写出 12-opcode VM 解释器并逐字符爆破出 flag（注意 word>>8 与 OR 语义）'),
       ('ezhtml', '2024 初赛', 'WASM：wasm2c → 环形异或从尾逆推 35 字节'),
       ('infantvm', '2022 初赛', 'angr 脚本能读懂，现场能改 find/avoid'),
       ('next-prime', '2023 初赛', '相邻素数 RSA + Coppersmith 已知高位'),
       ('Step_By_step', '2023 初赛', '分段组合：Coppersmith + GM 位加密 + RSA e=3'),
       ('EC_Party-I-chall', '2023 初赛', 'EC 复合阶 + 诱导错误点加 GCD 求 p,q + CRT（阅读级）'),
       ('breakMe', '2022 初赛', 'Håstad 广播推广 + CRT + Coppersmith'),
       ('unnamed_50x50_dp / unnamed_maze_lzss', '2022 初赛', '逆向验证规则后直接写求解器；花指令 patch + LZSS')],
 'D': [('奇怪的E', '2022 初赛', 'E/e 大小写比特编码，逐位还原 8bit 一组'),
       ('A_Small_Secret', '2023 初赛', 'b32 分段提取 + AES + docx document.xml 链'),
       ('unnamed_qrcode_stego', '2022 初赛', 'binwalk 分离 → 补 PNG 头 → 二维码 → hex 流程默写'),
       ('loopQR', '2023 初赛', '信道隐写（stegsolve）+ pyzbar 批量二维码'),
       ('神秘端口', '2023 初赛', 'USB HID 键盘流量还原独立完成'),
       ('EZ_ATEXEC', '2025 初赛方向', 'NTLMv2 导出 → hashcat → AES 解一层，后面缺附件的步骤写成清单'),
       ('Draw_what_you_like / Secret_Varied_Gif', '2024 初赛', '图片隐写变体，练检查顺序')],
}

HEAD = {
 'A': ('A｜二进制攻防（Pwn）', '全部 Pwn；ELF Reverse 兼援；进决赛后延伸到 AWD 里的二进制题 + patch。'),
 'B': ('B｜Web 与协议利用', '全部 Web；Misc 里偏渗透、SSRF、内网的题兼援；进决赛后延伸到 AWD Web + 靶场打点。'),
 'C': ('C｜密码与逆向（Crypto + VM/WASM/.NET）', '全部 Crypto + VM/WASM/.NET Reverse；帮 A 写利用脚本、跑 Z3；进决赛后延伸到决赛里的算法题、流量解密。'),
 'D': ('D｜杂项与调度（Misc + 平台）', '全部 Misc + 平台/提交/盯榜；编码签到、帮 B 爆破、整理 WP；进决赛后延伸到靶场信息收集、流量监控。'),
}

DISCIPLINE = {
 'A': ['- 单题 70 分钟还没有泄露，挂起换题或让 C 看反编译。',
       '- 先打通本地再打远程；远程崩了等超时再重连。',
       '- 写出的 exp 立刻丢共享文档，偏移和 libc base 写法写清楚。',
       '- 不接 Misc/Web 的"看一眼"请求，保持连续注意力。'],
 'B': ['- 有源码先审计，无源码先扫路径和报错。',
       '- 卡在"需要内网盲注"时，把报文和脚本交给 D 帮跑，自己切下一道 Web。',
       '- Java 题先确认协议（TCP 4 字节长度前缀 + Hessian2），不要当 PHP 乱打。',
       '- 每打通一条链，把 payload 模板存进队内脚本目录。'],
 'C': ['- Crypto 先花 10 分钟分类（e=3 / 多组 n / 不平衡 / LCG / 格），对不上就换 Reverse。',
       '- 格运算跑起来就不要盯着看，去开 VM。',
       '- A 需要算偏移、写小脚本时你是第一外援。',
       '- 队内库（rsa_util / lcg / coppersmith / vm_template）赛前放同一目录，赛时只调用不重写。'],
 'D': ['- 开赛先扫全部 Misc 和"看起来像编码"的题。',
       '- 长链做到某一层缺环境，把已解密文件丢共享盘，喊 C 或 B。',
       '- 不要自己去碰 Pwn 堆题。',
       '- 最后 30 分钟停止开新题，改为复核 flag 和归档。',
       '- 你是唯一提交人：记录每题首次提交时间。'],
}

BENCH = {
 'A': '不看 WP，90 分钟内打通一道 2023/2024 初赛 Pwn 的本地到 flag；10 分钟内给任意带 libc 的题补丁跑起来、本地交互通。',
 'B': '不看 WP，60 分钟内走完 very_easyphp 或等价 PHP 套娃，并独立写出一道 gopher POST。',
 'C': '三道 2024 Crypto 全部用自己的库复现；downcity 解释器是自己写的；LCG solve1–4 随机实例全部还原 seed。',
 'D': '任意未知编码/隐写 20 分钟内给出下一层文件；能从 pcap 导出 NetNTLMv2 并打出弱口令；测试日清单能独立执行。',
}

TOOLS = {
 'A': "pwntools、patchelf、pwninit、glibc-all-in-one(2.23/2.27/2.31)、pwndbg 或 gef、ROPgadget/ropper、one_gadget、seccomp-tools、qemu-user-static、IDA/Ghidra(反编译看漏洞即可)",
 'B': "Burp(必备)、PHP 7.4 与 8.x 本地各一套、Python requests + 自写 gopher 生成器、Java 8/11 + 一份 Hessian 序列化环境(能跑通模板即可)、jwt_tool、sqlmap(只作辅助，组合题上手写)",
 'C': "Python3 + pycryptodome + python-flint(Sage 作备份)、z3-solver、Ghidra/IDA/dnSpy、wabt(wasm2c)、队内库 rsa_util/lcg/coppersmith/vm_template",
 'D': "010 Editor/HxD、binwalk、foremost、exiftool、Wireshark/tshark、stegsolve、zbar、hashcat、john、Volatility 或 MemProcFS(会开镜像即可)、计时器、共享文档(飞书/Notion/hackmd)",
}

CROSS = """1. **签到归属**：编码/文件 → D；一眼 PHP → B；给个 n,e,c → C；给个 ELF 菜单 → A。争执不超过 1 分钟，队长指定。
2. **换人触发**：同一方向 40 分钟无新信息。A↔C 换 ELF 反编译；B↔D 换流量/爆破；C↔D 换解密脚本。
3. **禁止全员围一题**：0 解题最多 2 人看。
4. **脚本公有**：C 的 LCG/Coppersmith、B 的 gopher 生成器、A 的 exp 模板，赛前放同一目录。

共享文档每题一行：

```
题名 | 类型 | 负责人 | 状态 | 已有信息 | 下一步 | flag
```

状态只用：未开 / 在做 / 卡住 / 可交 / 放弃。"""

CAPTAIN = """四人里指定一人兼队长（建议 D 或 C，不要让 A 兼——Pwn 最吃连续注意力）。队长职责只有四件：

1. 开赛 3 分钟分题
2. 每 15 分钟收状态
3. 决定换人或放弃
4. 指定唯一交 flag 的人

技术学习仍按自己的岗位走。"""

HOWTO = """1. 登录 <https://ctf2.dasctf.com>，进入**练习中心**。
2. 本手册"刷题清单"里的题名就是平台题名：在对应分类（Pwn / Web / Crypto / Reverse / Misc）里按名字搜索即可找到。名字里带年份前缀的（如 `bjdctf_2020_babystack`）直接搜整串。
3. 点开题目 → 下载附件 → 本地做 → 平台提交 flag。提交成功才算这题完成。
4. 遇到搜不到的题名 / 附件缺失 / 环境题需要启动容器的，记录题名找队长汇总处理，不要卡住刷题节奏。
5. 建议开一个自己的刷题记录表（题名 / 一句话考点 / 完成日期 / 卡点），赛前这就是你的复习清单。"""

FLAG_RE = re.compile(r'(?:DASCTF|flag|NSSCTF|ctfshow)\{[^}\n]*\}', re.IGNORECASE)

def build_doc(role, buckets):
    title, mission = HEAD[role]
    n_total = sum(b['n'] for b in buckets)
    L = [f"# {title} —— ctf2 刷题训练手册", "",
         f"> **岗位使命**：{mission}",
         "> 题目全部来自 ctf2 平台练习中心，按本手册的**平台题名**搜索完成。",
         "> 刷题顺序 = 下面清单顺序（由易到难）；时间安排由队长统一布置。", "",
         "## 〇、怎么用这本手册", ""]
    L.append(HOWTO + "\n")
    L.append("## 一、必须掌握的知识点（按此顺序学，全部不能缺）\n")
    L.append(LEARN[role] + "\n")
    L.append("## 二、目标比赛情报（历年考点与出题套路）\n")
    L.append(INTEL[role] + "\n")
    L.append(f"## 三、刷题清单（共 {n_total} 题，按方向分组，从上往下刷）\n")
    for b in buckets:
        L.append(table(b, b['n']))
    L.append("## 四、验收题（必做，做完才算过关）\n")
    L.append("这些是目标比赛（研究生网络安全创新大赛 / DASCTF）历年真题，在平台对应 ground 里按题名搜索；找不到附件就找队长：\n")
    L.append("| 题名 | 届次 | 验收标准 |")
    L.append("|------|------|----------|")
    for nm, yr, std in ACCEPT[role]:
        L.append(f"| {nm} | {yr} | {std} |")
    L.append("")
    L.append("## 五、工具清单\n")
    L.append("```\n" + TOOLS[role] + "\n```\n")
    L.append("## 六、赛时纪律\n")
    L += DISCIPLINE[role] + [""]
    L.append("## 七、队长职责与交叉规则\n")
    L.append(CAPTAIN + "\n")
    L.append(CROSS + "\n")
    L.append("## 八、合格线自测（达到才算过关，不要凭感觉）\n")
    L.append("- " + BENCH[role] + "\n")
    L.append("---")
    L.append("*某一岗明显弱，就让该岗减「加分项」、加「必须会」的训练量，不要让另外三人降下来陪跑。*")
    return '\n'.join(L) + '\n'

# ---------------------------------------------------------------- package build
DIRN = {'A': 'A-二进制攻防', 'B': 'B-Web与协议', 'C': 'C-密码与逆向', 'D': 'D-杂项与调度'}
BUCKS = {'A': A_buckets, 'B': B_buckets, 'C': C_buckets, 'D': D_buckets}

report_src = open(os.path.join(ROOT, '.tmp', '赛题分析报告.md'), encoding='utf-8').read()
report_clean = FLAG_RE.sub('[FLAG已脱敏]', report_src)
report_clean = re.sub(r"分析环境：.*", "分析环境：离线（Python + 标准命令行工具）", report_clean)
report_clean = re.sub(r"- 工具链：.*", "- 工具链：Python 3 + pycryptodome、WSL 命令行（file/readelf/objdump + 直接运行 ELF 交互）、手写反汇编分析。", report_clean)
report_clean = report_clean.replace("ctf-forge `codec --op unb32` 解", "base32 解")
report_clean = report_clean.replace("（工作区 KNOWLEDGE.md 有对应技术卡 usb.hid_keyboard）", "")
report_clean = report_clean.replace("本工作区已验证", "队内已验证")
report_clean = report_clean.replace("证明本工作区可替代", "已验证纯 Python 可替代")
report_clean = re.sub(r"b'[^']*'", "b'[FLAG已脱敏]'", report_clean)

os.makedirs(os.path.join(HERE, 'packages'), exist_ok=True)
summary = []
for role in 'ABCD':
    used.clear()
    doc = build_doc(role, BUCKS[role])
    d = os.path.join(HERE, 'packages', DIRN[role])
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, '训练手册.md'), 'w', encoding='utf-8').write(doc)
    open(os.path.join(d, '赛题分析报告-参考.md'), 'w', encoding='utf-8').write(
        "# 赛题分析报告（参考材料，flag 已脱敏）\n\n" + report_clean)
    zp = os.path.join(HERE, 'packages', f'{DIRN[role]}.zip')
    with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as z:
        for fn in ('训练手册.md', '赛题分析报告-参考.md'):
            z.write(os.path.join(d, fn), f'{DIRN[role]}/{fn}')
    n = sum(b['n'] for b in BUCKS[role])
    summary.append((zp, n, os.path.getsize(zp)))
for zp, n, sz in summary:
    print(f'{zp}  {n}题  {sz/1024:.0f}KB')
