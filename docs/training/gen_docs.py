# -*- coding: utf-8 -*-
"""Generate four role training docs (A/B/C/D) from the CTF2 challenge catalog.

Training volume comes from on-disk challenges/ctf2/ archives; the plan-named
acceptance challenges live on the platform (buuctf-real ground) and are listed
separately with fetch instructions.
"""
import json, os, re, random
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
cat = json.load(open(os.path.join(HERE, 'catalog.json'), encoding='utf-8'))

# reload solve attack info for solved rows
def attack_of(d):
    p = os.path.join(ROOT, d['dir'], 'solve', 'result.json')
    if not os.path.exists(p):
        return None
    try:
        r = json.load(open(p, encoding='utf-8'))
        return r.get('attack') or r.get('method') or ''
    except Exception:
        return None

DIFF_RANK = {'Easy': 0, 'Middle': 1, 'MIDDLE': 1, 'Normal': 1, 'Medium': 1,
             'Hard': 2, 'HARD': 2, 'Difficult': 3, 'Hell': 4}

used = set()
def rel(d):
    return d['dir'][len('challenges/ctf2/'):]

def pick(bucket, pool, n, prefer_files=True):
    """pick up to n entries from pool matching any keyword; fall back to rest of pool."""
    kws = [k.lower() for k in bucket.get('kw', [])]
    hits, rest = [], []
    for x in pool:
        if id(x) in used:
            continue
        nm = x['name'].lower()
        if any(k in nm for k in kws):
            hits.append(x)
        else:
            rest.append(x)
    src = hits if len(hits) >= n else hits + rest
    picked = []
    for x in src:
        if len(picked) >= n:
            break
        if prefer_files and not x['files'] and len(src) - len(picked) > n - len(picked) and x in hits:
            # keep files-less only if we would otherwise fall short
            continue
        if id(x) in used:
            continue
        used.add(id(x))
        picked.append(x)
    return picked

def rows_for(bucket, pool, n):
    picked = pick(bucket, pool, n)
    def key(x):
        dr = DIFF_RANK.get(x['difficulty'] or '', 1)
        st = 0 if x['status'] == 'unattempted' else 1
        return (dr, st, x['name'].lower())
    picked.sort(key=key)
    out = []
    for i, x in enumerate(picked, 1):
        st = x['status']
        if st == 'solved' or st == 'recovered_noisy':
            a = attack_of(x) or ''
            stx = '★已解'
            note = f'复盘对照: {a}' if a else '复盘对照: solve/result.json'
        else:
            stx, note = '待打', ''
            if st == 'blocked_archive':
                note = '附件是加密压缩包，先按 D 岗 zip 攻击拿密码'
        if not x['files']:
            note = (note + '；' if note else '') + '附件未归档，去平台下载'
        pos = rel(x)
        out.append((i, x['name'], x['difficulty'] or '—', stx, pos, note))
    return out

GOALS = {
 # A
 '环境与栈基础（识别→溢出→ret2libc）': '先用 file/checksec 摸清保护；溢出长度精确算；puts@plt+got 泄 libc → system("/bin/sh")。前 10 题允许查资料，之后不看资料打通。',
 'ROP 与栈迁移': 'ret 对齐、__libc_csu_init、leave;ret 迁 bss、SROP；把通用片段沉淀成自己的 exp 模板。',
 '格式化字符串': '%p 找偏移、%hn/%hhn 写 got；无限输入的标准 fmt 全部打通，再挑战单次写入的题。',
 '堆利用 glibc2.23（fastbin/unsorted/UAF/unlink）': '每题先数 add/delete/edit/show 配额和 size 限制；unsorted bin 泄 libc；fastbin attack 打 __malloc_hook/__free_hook。',
 '堆利用 glibc2.31（tcache）与泄露链': 'tcache 投毒 + key 绕过；配额不够填 tcache 时找题目给的泄露（越界 show/格式化/礼物函数），不死磕 unsorted。',
 'ORW / shellcode / 沙箱': 'seccomp-tools dump 先看禁了什么；写出最短 ORW ROP，不依赖 /bin/sh；ascii_shellcode 会压缩。',
 '异构与内核（MIPS / driver，选学）': '选学一项就够：MIPS 大端 ret2libc，或 babydriver 型 cred UAF。第四周不开新知识。',
 # B
 'PHP 审计与绕过（弱比较/解析/反序列化/执行）': '能按数据流复述每条链：入口→过滤→sink；弱比较/0e、parse_url 畸形、unserialize magic 全部本地验证过一遍。',
 'SSRF 与内网二次利用（gopher/Redis/Memcached）': '独立写出 gopher POST 生成器（Content-Length、CRLF、双重 URL 编码）；Redis 未授权写 shell 全流程走通一次。',
 'SQL 注入（报错/盲注/绕过）': '手注出库名表名；空格/引号/关键字绕过有预案；时间盲注报文生成器提前写好。',
 'Java / 反序列化 / RPC': '先认协议再动手（TCP 4 字节长度前缀 + Hessian2）；Hessian2 gadget 链能改模板跑通；shiro/log4j 特征背熟。',
 '鉴权与会话（JWT/cookie/模板注入）': 'JWT 三种改法（RS256→HS256、none、kid）+ SSTI 通用 payload 背熟。',
 '综合组合拳与无谱题（限时训练）': '每题限时 40 分钟：先认语言/框架 → 扫路径看报错 → 审计，写出 3 行下一步计划再动手。',
 # C
 'RSA 基础攻击（e=3/共模/广播/dp/Fermat/Wiener）': '全部收进 rsa_util.py：输入参数自动判型；每题把攻击式子独立推导一遍再写代码。',
 '格与 Coppersmith（已知高位/低位/不平衡 n）': '合成参数能解、真题参数能解，2 分钟内出根；格维度和权重自己会设，不只调包。',
 'PRNG / LCG（必须全部手写还原）': 'solve1–4 写成四个函数，随机实例全部还原 seed；MT19937 untemper 手写一遍。',
 '其他密码（AES/Rabin/ECC/古典）与 dasbook 教学链': '判型优先：拿到密文先跑识别（二次剩余/分组长度/熵）；dasbook 教学题当天做完当热身。',
 'REVERSE：VM / WASM / .NET / PYC / APK': '先列 opcode 表再跑通已知输入；wasm 用 wasm2c；.NET 用 dnSpy；每个 VM 题都产出一份解释器代码。',
 'REVERSE：花指令/反调试/SMC 与算法还原（dasbook 13 章）': '看到 75 03 74 01 类先 patch 再反编译；还原规则后直接写求解器，不要动态调一整天。',
 # D
 '编码全家桶与古典密码（开赛武器）': '20 分钟内给出下一层文件；每种编码认得出特征（b32 字符集、morse 音、零宽字符、大小写比特）。',
 '图片隐写（LSB/宽高/盲水印/附加数据）': '固定检查顺序：宽高→LSB→通道分离→附加段→盲水印；工具链不假手他人。',
 'ZIP 与文件攻击（伪加密/CRC32/字典/掩码）': '伪加密秒修；CRC32 短内容碰撞脚本化；rockyou 字典流程肌肉记忆。',
 '流量分析（HTTP/TLS/USB 键盘鼠标/webshell 流量）': '协议分层→跟踪流→导出对象三板斧；USB HID 键盘还原独立完成一次。',
 '音频隐写（MP3/频谱/波形/摩斯音频）与文档隐写': '频谱图/波形图都看一遍再下结论；文档隐写检查注释、隐藏文字、附录。',
 '取证与长链（内存/磁盘/NTLM→AES 流程）': 'NTLMv2 导出→hashcat→解密下一层按清单走；知道下一层证据在哪种工件里。',
}

def table(bucket, pool, n, goal=None):
    goal = bucket.get('goal') or GOALS.get(bucket['title'], goal or '')
    rows = rows_for(bucket, pool, n)
    lines = [f"### {bucket['week']}｜{bucket['title']}（{len(rows)} 题）", "",
             f"**训练目标**：{goal}", "",
             "| # | 题名 | 难度 | 状态 | 位置 | 备注 |",
             "|---|------|------|------|------|------|"]
    for i, nm, df, stx, pos, note in rows:
        note = note.replace('|', '/')
        nm = nm.replace('|', '/')
        lines.append(f"| {i} | {nm} | {df} | {stx} | `{pos}` | {note} |")
    return '\n'.join(lines) + '\n'

def ground_pool(catname, grounds=('buuctf',)):
    return [x for x in cat if x['category'] == catname and x['ground'] in grounds]

def dasbook_pool(chapters):
    return [x for x in cat if x['ground'] == 'dasbook'
            and any(c in x['category'] for c in chapters)]

# ---------------------------------------------------------------- A: PWN
A_buckets = [
    dict(week='第1周', title='环境与栈基础（识别→溢出→ret2libc）', n=26,
         kw=['babystack', 'stack', 'bof', 'overflow', 'ret2', 'level', 'warmup', 'pwn1', 'hello', 'int overflow', 'ciscn_2019_c', 'test_your_', 'nc ', 'when_did_you'],
         pool=ground_pool('PWN') + dasbook_pool(['第15章'])),
    dict(week='第1周', title='ROP 与栈迁移', n=14,
         kw=['rop', 'gadget', 'migrate', 'srop', 'leave', 'csu', 'move', 'finall'],
         pool=ground_pool('PWN') + dasbook_pool(['第15章'])),
    dict(week='第1周', title='格式化字符串', n=10,
         kw=['fmt', 'format', 'playfmt', 'printf'],
         pool=ground_pool('PWN') + dasbook_pool(['第15章'])),
    dict(week='第2周', title='堆利用 glibc2.23（fastbin/unsorted/UAF/unlink）', n=22,
         kw=['heap', 'babyheap', 'note', 'uaf', 'fastbin', 'unlink', 'freenote', 'book', 'babyfeng'],
         pool=ground_pool('PWN') + dasbook_pool(['第16章'])),
    dict(week='第2周', title='堆利用 glibc2.31（tcache）与泄露链', n=16,
         kw=['tcache', 'children', 'tear', 'ctf2019', 'hole', 'yellow', 'iron', 'one_gadget', 'libc', 'leak', 'got', 'hijack'],
         pool=ground_pool('PWN')),
    dict(week='第3周', title='ORW / shellcode / 沙箱', n=12,
         kw=['orw', 'shellcode', 'seccomp', 'sandbox', 'shell', 'execve'],
         pool=ground_pool('PWN')),
    dict(week='第3周', title='异构与内核（MIPS / driver，选学）', n=8,
         kw=['mips', 'driver', 'kernel', 'arm', 'qemu'],
         pool=ground_pool('PWN') + ground_pool('REVERSE') + dasbook_pool(['第17章'])),
]

# ---------------------------------------------------------------- B: WEB
B_buckets = [
    dict(week='第1周', title='PHP 审计与绕过（弱比较/解析/反序列化/执行）', n=26,
         kw=['php', 'unserialize', 'md5', 'weak', 'strcmp', 'include', 'upload', 'bypass', 'wakeup', 'clone', 'think', 'laravel', 'eval', 'filter', 'rce', 'web_shell', 'webshell'],
         pool=ground_pool('WEB')),
    dict(week='第1周', title='SSRF 与内网二次利用（gopher/Redis/Memcached）', n=14,
         kw=['ssrf', 'redis', 'gopher', 'curl', 'url', 'memcached', 'proxy', 'intranet', '内网'],
         pool=ground_pool('WEB')),
    dict(week='第1周', title='SQL 注入（报错/盲注/绕过）', n=12,
         kw=['sql', 'inject', 'sqli', 'blind', 'quine', 'login', 'db'],
         pool=ground_pool('WEB')),
    dict(week='第2周', title='Java / 反序列化 / RPC', n=14,
         kw=['java', 'jaba', 'javalib', 'spring', 'hessian', 'jndi', 'rmi', 'deser', 'Deserialize', 'jre', 'shiro', 'log4j', 'easyjaba'],
         pool=ground_pool('WEB')),
    dict(week='第2周', title='鉴权与会话（JWT/cookie/模板注入）', n=12,
         kw=['jwt', 'token', 'session', 'cookie', 'auth', 'ssti', 'flask', 'jinja', 'pickle', 'node', 'express', 'template', 'render'],
         pool=ground_pool('WEB')),
    dict(week='第3周', title='综合组合拳与无谱题（限时训练）', n=16,
         kw=['calc', 'shop', 'game', 'index', 'checkin', 'cool', 'go', 'proxy', 'easy_web', 'baby_web', 'ez_'],
         pool=ground_pool('WEB')),
]

# ---------------------------------------------------------------- C: CRYPTO + REVERSE
C_buckets = [
    dict(week='第1周', title='RSA 基础攻击（e=3/共模/广播/dp/Fermat/Wiener）', n=26,
         kw=['rsa', 'wiener', 'fermat', 'broadcast', 'common', 'dp', 'hastad', 'rabin'],
         pool=ground_pool('CRYPTO') + dasbook_pool(['第06章'])),
    dict(week='第2周', title='格与 Coppersmith（已知高位/低位/不平衡 n）', n=12,
         kw=['copper', 'lattice', 'boneh', 'durfee', 'stereotyped', 'partial', 'padding', 'leak', 'unlock', 'small'],
         pool=ground_pool('CRYPTO')),
    dict(week='第2周', title='PRNG / LCG（必须全部手写还原）', n=12,
         kw=['lcg', 'rand', 'random', 'mt19937', '伪随机', 'predict', 'seed', '四层'],
         pool=ground_pool('CRYPTO') + dasbook_pool(['第06章'])),
    dict(week='第3周', title='其他密码（AES/Rabin/ECC/古典）与 dasbook 教学链', n=14,
         kw=['aes', 'des', 'rc4', 'rabin', 'ecc', 'elliptic', 'hill', 'affine', 'vigenere', 'playfair', 'fence', 'morse', 'classical', 'md5', 'hash'],
         pool=ground_pool('CRYPTO') + dasbook_pool(['第05章'])),
    dict(week='第3周', title='REVERSE：VM / WASM / .NET / PYC / APK', n=14,
         kw=['vm', 'wasm', 'dotnet', 'net', 'pyc', 'python', 'apk', 'java', 'kotlin', 'jadx', 'exe', 'crackme', 'key'],
         pool=ground_pool('REVERSE') + dasbook_pool(['第12章']) + [x for x in cat if x['ground'] == 'n1book']),
    dict(week='第3周', title='REVERSE：花指令/反调试/SMC 与算法还原（dasbook 13 章）', n=10,
         kw=['花指令', 'smc', '反调试', 'maze', '迷宫', 'z3', 'angr', 'sudoku', '约束', 'game', 'baby_rev', 're1', 're2'],
         pool=ground_pool('REVERSE') + dasbook_pool(['第13章'])),
]

# ---------------------------------------------------------------- D: MISC
D_buckets = [
    dict(week='第1周', title='编码全家桶与古典密码（开赛武器）', n=18,
         kw=['base', 'encode', 'morse', '键盘', 'zero', 'unicode', 'charset', 'code', '古', 'password', 'cipher', 'E:', 'e_e', '奇怪的'],
         pool=ground_pool('MISC') + dasbook_pool(['第05章'])),
    dict(week='第1周', title='图片隐写（LSB/宽高/盲水印/附加数据）', n=20,
         kw=['steg', 'lsb', 'png', 'gif', 'jpg', 'img', 'watermark', '盲水印', '宽', '高', 'picture', 'photo', 'qrcode', '二维码', 'qr'],
         pool=ground_pool('MISC') + dasbook_pool(['第07章'])),
    dict(week='第1周', title='ZIP 与文件攻击（伪加密/CRC32/字典/掩码）', n=12,
         kw=['zip', 'crc', '压缩', 'rar', '加密的', 'pass'],
         pool=ground_pool('MISC') + dasbook_pool(['第08章'])),
    dict(week='第2周', title='流量分析（HTTP/TLS/USB 键盘鼠标/webshell 流量）', n=16,
         kw=['pcap', 'usb', 'keyboard', 'mouse', '流量', 'http', 'tls', 'wifi', 'network', '流量包', 'hid', '端口'],
         pool=ground_pool('MISC') + dasbook_pool(['第09章'])),
    dict(week='第2周', title='音频隐写（MP3/频谱/波形/摩斯音频）与文档隐写', n=12,
         kw=['mp3', 'wav', 'audio', '频谱', '声音', 'music', 'pdf', 'word', 'doc', '文档'],
         pool=ground_pool('MISC') + dasbook_pool(['第07章'])),
    dict(week='第3周', title='取证与长链（内存/磁盘/NTLM→AES 流程）', n=12,
         kw=['mem', 'memory', 'forensi', 'disk', 'ntlm', 'kerbero', '取证', 'vmdk', 'e01', 'volatility', '镜像'],
         pool=ground_pool('MISC') + dasbook_pool(['第10章'])),
]

HEAD = {
 'A': ('A｜二进制攻防（Pwn）', '全部 Pwn；ELF Reverse 兼援；进决赛后延伸到 AWD 二进制题与 patch。'),
 'B': ('B｜Web 与协议利用', '全部 Web；Misc 里偏渗透/SSRF/内网的题兼援；进决赛后延伸到 AWD Web 与靶场打点。'),
 'C': ('C｜密码学 + 逆向（VM/WASM/.NET）', '全部 Crypto + VM/WASM/.NET Reverse；帮 A 写利用脚本、跑 Z3；进决赛后延伸到算法题与流量解密。'),
 'D': ('D｜杂项与调度', '全部 Misc + 平台/提交/盯榜；编码签到、帮 B 爆破、整理 WP；进决赛后延伸到靶场信息收集与流量监控。'),
}

ACCEPT = {
 'A': [('springboard', '[DASCTF 2024暑期挑战赛] 本地已有: buuctf/PWN/[dasctf_2024暑期挑战赛…]/springboard，读代码即可'),
       ('stack (2022 初赛)', '纸面也要走完整条 ret2libc 链'),
       ('stack_and_heap (2022)', '重点走栈迁移段'),
       ('cancanneed_new', '交互复杂的完整堆链'),
       ('easy_ssp', 'stack smashing 泄露固定地址'),
       ('story / ASadStory', '只学 UAF + 越界 show 泄 PIE 两步'),
       ('mips_fmt', '有时间再碰'),
       ('kernel-network (HRPUAF.ko)', 'babydriver 型内核题')],
 'B': [('very_easyphp', '整条 PHP 套娃链讲清楚，本地全部验证'),
       ('ssssrf', '独立写出 gopher 报文生成器'),
       ('Bad_Memcached', 'POP + CRLF + curl 串联看懂'),
       ('babyql', 'Java hashCode 短碰撞')],
 'C': [('EZ_RSA_5', 'px+qy=n+1 型互逆元/线性式'),
       ('real_rsa_2', '不平衡 n 分解后解密'),
       ('insecure_padding', 'Coppersmith 已知填充，2 分钟内出根'),
       ('2022 四层挑战 ch1–ch4', 'LCG 逐层还原，写成 4 个函数'),
       ('downcity', '自己写出 VM 解释器并打出 flag'),
       ('ezhtml', 'WASM 环形异或从尾逆推 35 字节'),
       ('infantvm', 'angr 脚本能读懂、现场能改 find/avoid')],
 'D': [('奇怪的E', '大小写比特编码'),
       ('A_Small_Secret', 'b32 分段提取'),
       ('unnamed_qrcode_stego', '二维码定位符修复流程默写'),
       ('神秘端口', 'USB HID 键盘流量还原'),
       ('EZ_ATEXEC', 'NTLMv2 导出→hashcat→AES 解一层')],
}

DISCIPLINE = {
 'A': ['- 单题 70 分钟还没有泄露，挂起换题或让 C 看反编译。',
       '- 先打通本地再打远程；远程崩了等超时再重连。',
       '- exp 立刻丢共享文档，偏移和 libc base 写法写清楚。',
       '- 不接 Misc/Web 的“看一眼”请求，保持连续注意力。'],
 'B': ['- 有源码先审计，无源码先扫路径和报错。',
       '- 卡在“需要内网盲注”时，把报文和脚本交给 D 帮跑，自己切下一道 Web。',
       '- Java 题先确认协议（TCP 长度前缀 + Hessian2），不要当 PHP 乱打。',
       '- 每打通一条链，把 payload 模板存进队内脚本目录。'],
 'C': ['- Crypto 先花 10 分钟分类（e=3 / 多组 n / 不平衡 / LCG / 格），对不上就换 Reverse。',
       '- 格运算跑起来就不要盯着看，去开 VM。',
       '- A 需要算偏移、写小脚本时你是第一外援。',
       '- 队内库（rsa_util / lcg / coppersmith / vm_template）赛前放共享目录，赛时只许调用不许现场重写。'],
 'D': ['- 开赛先扫全部 Misc 和“看起来像编码”的题。',
       '- 长链做到某一层缺环境，把已解密文件丢共享盘，喊 C 或 B。',
       '- 不要自己去碰 Pwn 堆题。',
       '- 最后 30 分钟停止开新题，改为复核 flag 和归档。',
       '- 唯一提交人是你：记录每题首次提交时间。'],
}

BENCH = {
 'A': '不看 WP，90 分钟内打通一道 2023/2024 初赛 Pwn 的本地到 flag；10 分钟内给任意带 libc 的题补丁跑起来、本地交互通。',
 'B': '不看 WP，60 分钟内走完 very_easyphp 或等价 PHP 套娃，并独立写出一道 gopher POST。',
 'C': '三道 2024 Crypto 全部用自己的库复现；downcity 解释器是自己写的；LCG solve1–4 随机实例全部还原 seed。',
 'D': '任意未知编码/隐写 20 分钟内给出下一层文件；能从 pcap 导出 NetNTLMv2 并打出弱口令；测试日清单能独立执行。',
}

TOOLS = {
 'A': 'pwntools、patchelf、pwninit、glibc-all-in-one(2.23/2.27/2.31)、pwndbg 或 gef、ROPgadget/ropper、one_gadget、seccomp-tools、qemu-user-static、IDA/Ghidra(只看漏洞点)',
 'B': 'Burp(必备)、PHP 7.4 与 8.x 本地各一套、Python requests + 自写 gopher 生成器、Java 8/11 + Hessian 环境(跑通模板即可)、jwt_tool、sqlmap(只辅助)',
 'C': 'Python3 + pycryptodome + python-flint(Sage 备份)、z3-solver、Ghidra/IDA/dnSpy、wabt(wasm2c)、队内库 rsa_util/lcg/coppersmith/vm_template',
 'D': '010 Editor/HxD、binwalk、foremost、exiftool、Wireshark/tshark、stegsolve、zbar、hashcat、john、Volatility 或 MemProcFS(会开镜像即可)、计时器 + 共享文档',
}

LEARN = {
 'A': """1. **环境与识别（2 天内完成）**：file/checksec/readelf -d/ldd；patchelf + glibc-all-in-one（2.23、2.27、2.31）；pwninit、pwntools 模板；pwndbg 下断在 read/malloc/free。菜单题先数 add/delete/edit/show 的次数和 size 限制。
2. **栈利用（第 1 周主线）**：溢出长度精确算；leave;ret 迁移 bss；ret 对齐；puts@plt+got 泄 libc；one_gadget 约束验证，不行就 ORW；partial overwrite 低 2 字节回 main。
3. **堆利用（第 2 周主线，分版本记）**：2.23 fastbin 单双链、double free、unsorted 泄 libc、__malloc_hook/__free_hook；2.31 tcache 7 个、key 检测、UAF、tcache 投毒，配额不够别死磕 unsorted，找题目给的泄露。
4. **格式化字符串与沙箱（穿插）**：%p 泄栈/libc，%n/%hn/%hhn 写；seccomp-tools dump，禁 execve 走 open/openat+read+write 最短 ORW ROP。
5. **加分项（第 3 周有余力，学一项就够）**：内核 babydriver 型（ioctl 改对象大小、cred UAF、改 uid）；异构 MIPS 大端 + qemu-user-static、无 NX 时 fmt 写栈 shellcode。第 4 周不开新知识。""",
 'B': """1. **PHP 审计与绕过（第 1 周，按数据流记）**：`==` 弱比较/0e md5/数组绕 strcmp；parse_url 畸形、basename、pathinfo；preg_replace 残留、黑名单、intval 截断；create_function/eval/assert/preg_replace /e；mt_srand(时间戳前缀) 预测 mt_rand；unserialize + __destruct/__wakeup/__toString。
2. **SSRF 与内网二次利用（第 1 周后半）**：file://、dict://、gopher://；gopher 打 HTTP POST（Content-Length、CRLF、双重 URL 编码）；打 Redis/FastCGI/Memcached；回环绕过 127.0.0.1/0.0.0.0/[::]/nip.io；时间盲注先把报文生成器写对。
3. **鉴权与语言特性（穿插）**：JWT RS256 公钥当 HS256 secret、none、kid 注入；Java hashCode 短碰撞；Node 模板注入/file://+pathname 编码/原型链；Python SSTI、沙箱绕过。
4. **Java/RPC（第 2 周主线，2025 已考）**：认协议——TCP 4 字节长度前缀 + Hessian2；入口 XXL-RPC、Motan、gRPC-Web 代理；Hessian2 反序列化 → 已知 gadget(Rome) → JNDI；gRPC-Web `target=` 绕 http(s) 前缀、base64 打内网。能抓报文、改模板、讲清链条即可，不必从零造 gadget。
5. **代码审计习惯**：路由和入口参数 → 搜 eval|system|exec|passthru|popen|unserialize|file_get_contents|curl|include|create_function → 过滤函数在哪一层 → 有无二次渲染、有无内网接口。""",
 'C': """1. **数论与 RSA 基础（第 1 周前 3 天）**：模逆、CRT、欧拉函数、阶；e=3 开立方与短填充；共模不同 e、共 e 广播+CRT；dp/dq 拆 n；px+qy=n+1 型线性式；相邻素数 Fermat。
2. **格与 Coppersmith（第 1 周后半～第 2 周）**：LLL 直观理解；Howgrave-Graham + 已知高位/低位；不平衡 n（p≈N^{2/3}）；apbq/正交格会设维度和权重。实现优先 Python + python-flint，Sage 备份。
3. **PRNG/LCG（必须手写，不要现场推）**：一层已知 a,b,N 逆推 seed；两输出未知 b；三输出模逆求 a；高阶差分+GCD 求 N。solve1–4 写成四个函数，随机实例全部还原。
4. **其他密码（知道判题即可）**：二次剩余/Rabin；Goldwasser-Micali 位加密；EC 只到“复合阶 + 错误点加再 GCD”的阅读级。
5. **逆向：VM/WASM/.NET/算法还原（穿插）**：自研 VM 先列 opcode 表→已知输入跑通→爆破或 Z3；注意操作数宽度（downcity 是 word>>8）、AND/OR 写反、条件跳转方向；WASM wasm2c 或直读，环形异或从尾逆推；.NET dnSpy 注意 Assembly.Load；花指令先 patch（75 03 74 01 类）再反编译；格盘/DP/迷宫还原规则后直接写求解器，不要动态调一整天。""",
 'D': """1. **编码与文件（开赛武器，2 天练熟）**：hex、b32、b58、b64、b85、uu、xx、morse、零宽、大小写比特（E/e）；file/binwalk/foremost；PNG 头 89 50 4E 47；ZIP 伪加密；二维码定位符缺失修复，qrcode/zbar 批量；LSB、stegsolve、steghide、附录 zip。
2. **流量分析（第 1 周）**：Wireshark 按协议分层、跟踪流、导出对象；HTTP 重组、WebSocket、USB HID 键盘映射；看到 NTLMSSP/Kerberos/SMB/DCERPC 走 2025 那条链的前半。
3. **Windows/AD 长链（第 2 周，2025 出过 0 解题，按步骤记）**：pcapng 找 NTLMSSP → 导出 NetNTLMv2 → hashcat -m 5600 + rockyou → 密码解 DCERPC 后续层 → 计划任务 XML（utf-16le）→ AES-CBC（key/IV 在题面或 XML）→ 自研流密码（记录每字节几轮、有无密文反馈）→ Kerberos keytab、SMB2 session key 大小端 → 图片再隐写。
4. **取证短链（穿插）**：内存先找进程列表、浏览器、密码框、cmdline；places.sqlite、USB 数位板坐标、VeraCrypt+keyfile；不要求写插件，要求知道下一层证据在哪种工件里。
5. **调度与平台（岗位本身）**：测试日全员能登、能交、flag 格式确认、附件能下；赛时唯一提交人，记录每题首次提交时间；盯榜——某题解出数突然涨，喊对应负责人；赛后 WP 骨架：题名、附件哈希、命令、payload。
6. **轻量支援**：hashcat/john 常见 mode；按 B 给的字典爆破 HTTP；按 A 给的命令跑远程连通测试。""",
}

WEEK_PLAN = {
 'A': "| 周 | 主线 | 验收 |\n|---|------|------|\n| 1 | 三套 libc 环境 + 栈迁移两道 + fmt | 10 分钟内补丁跑起来、本地交互通 |\n| 2 | 2.23/2.31 堆各一道 | cancanneed 全链 / easy_ssp |\n| 3 | ORW + 选学内核或 MIPS 一项 | 最短 ORW ROP 独立写出 |\n| 4 | 只复习自己写过的 exp | 8 小时限时赛（第 4 周）|",
 'B': "| 周 | 主线 | 验收 |\n|---|------|------|\n| 1 | PHP 审计 + very_easyphp + gopher 生成器 | 链路全程可讲 |\n| 2 | Memcached/SSRF 串链 + Java Hessian 认协议 | Bad_Memcached 看懂 |\n| 3 | gRPC-Web / JWT / 源码审计限时 | 60 分钟一道审计题 |\n| 4 | 只复习自己打通的链 | 8 小时限时赛（第 4 周）|",
 'C': "| 周 | 主线 | 验收 |\n|---|------|------|\n| 1 | RSA+LCG 队内库 + EZ_RSA_5 | 库函数全部自带随机自测 |\n| 2 | Coppersmith + insecure_padding + downcity VM | 2 分钟内出根 |\n| 3 | real_rsa_2 + ezhtml + 花指令阅读 | VM 解释器自己写 |\n| 4 | 只跑自己的库 | 8 小时限时赛（第 4 周）|",
 'D': "| 周 | 主线 | 验收 |\n|---|------|------|\n| 1 | 编码全家桶 + 奇怪的E + 流量入门 | 20 分钟出下一层 |\n| 2 | NTLMv2→hashcat→AES；HID 键盘 | EZ_ATEXEC 前半独立完成 |\n| 3 | 8 小时模拟里当调度，补 WP 模板 | 零提交失误 |\n| 4 | 全真模拟提交与盯榜 | 8 小时限时赛（第 4 周）|",
}

def doc(role, buckets):
    title, mission = HEAD[role]
    lines = [f"# {title} —— ctf2 赛题训练清单", "",
             f"> **岗位使命**：{mission}",
             "> 全部训练题来自 ctf2 平台（ctf2.dasctf.com 练习中心，BUUCTF/DASCTF grounds）。",
             "> 本地已归档的题直接按 `位置` 列打开目录（`challenges/ctf2/` 下）。",
             "> 状态列含义：**待打**＝先自己做；**★已解**＝队里有解题记录（做完再看 `solve/result.json` 的攻击手法对照）；**曾卡**＝上次没解出来，重点练。", ""]
    lines.append("## 一、学什么、学到什么程度\n")
    lines.append(LEARN[role] + "\n")
    lines.append("## 二、训练题表（共 {} 题）\n".format(sum(b['n'] for b in buckets)))
    for b in buckets:
        lines.append(table(b, b['pool'], b['n'], b.get('goal', '')))
    lines.append("## 三、平台验收题（必须完成）\n")
    lines.append("这些是 2022–2025 决赛/初赛真题，在平台练习中心对应 ground 里，附件未归档的找队长用 `ctf-forge.exe ctf2` 或练习中心下载：\n")
    lines.append("| 题名 | 验收标准 |")
    lines.append("|------|----------|")
    for nm, std in ACCEPT[role]:
        lines.append(f"| {nm} | {std} |")
    lines.append("")
    lines.append("## 四、周计划\n")
    lines.append(WEEK_PLAN[role] + "\n")
    lines.append("## 五、工具清单\n")
    lines.append("```\n" + TOOLS[role] + "\n```\n")
    lines.append("## 六、赛时纪律\n")
    lines += DISCIPLINE[role] + [""]
    lines.append("## 七、合格线自测（达到才算过关，不要凭感觉）\n")
    lines.append("- " + BENCH[role] + "\n")
    lines.append("---")
    lines.append("*交叉规则备忘：签到归属——编码/文件→D；一眼 PHP→B；给个 n,e,c→C；给个 ELF 菜单→A，争执不超 1 分钟由队长指定。同一方向 40 分钟无新信息换人；0 解题最多 2 人看；C 的 LCG/Coppersmith、B 的 gopher 生成器、A 的 exp 模板赛前放同一目录。*")
    return '\n'.join(lines) + '\n'

random.seed(42)
for role, buckets in [('A', A_buckets), ('B', B_buckets), ('C', C_buckets), ('D', D_buckets)]:
    used.clear()
    out = os.path.join(HERE, {'A': 'A-二进制攻防.md', 'B': 'B-Web与协议.md',
                              'C': 'C-密码与逆向.md', 'D': 'D-杂项与调度.md'}[role])
    open(out, 'w', encoding='utf-8').write(doc(role, buckets))
    print('wrote', out, sum(b['n'] for b in buckets), '题')
